import logging

log = logging.getLogger(__name__)
log.setLevel(logging.INFO)

from cbint.utils.daemon import CbIntegrationDaemon, ConfigurationError
from cbint.utils.detonation.binary_queue import (SqliteQueue,
                                                 SqliteFeedServer,
                                                 BinaryDatabaseController)
from cbint.utils.detonation.binary_analysis import (CbAPIHistoricalProducerThread,
                                                    CbAPIUpToDateProducerThread,
                                                    QuickScanThread,
                                                    DeepAnalysisThread)
import cbint.utils.feed
import cbint.utils.cbserver
import os.path
from threading import Event, Thread
from time import sleep
from logging.handlers import RotatingFileHandler
import datetime
import socket
import time

try:
    import simplejson as json
except ImportError:
    import json

from cbapi.response import CbResponseAPI, Feed
from cbapi.example_helpers import get_object_by_name_or_id
from cbapi.errors import ServerError


class IntegrationError(Exception):
    pass


def touch(path):
    try:
        os.utime(path, None)
    except:
        open(path, 'a').close()


class FeedSyncRunner(Thread):
    """
    performs feed synchronization logic
    synchronizes a feed using the provided cb_api reference
    sync_needed should be set to true when a sync is needed
    """
    def __init__(self, cb_api, feed_name, dirty_event, interval=15):
        Thread.__init__(self)
        self.__cb = cb_api
        self.__feed_name = feed_name
        self.__interval = int(interval)
        self.sync_needed = False
        self.sync_supported = False
        self.dirty_event = dirty_event
        self.daemon = True

    def run(self):
        while True:
            sleep(self.__interval)

            if self.dirty_event.is_set():
                self.dirty_event.clear()
                log.info("synchronizing feed: %s" % self.__feed_name)
                self.__cb.feed_synchronize(self.__feed_name, False)


class DetonationDaemon(CbIntegrationDaemon):
    def __init__(self, name, **kwargs):
        work_directory = kwargs.pop('work_directory', None)
        CbIntegrationDaemon.__init__(self, name, **kwargs)
        self.cb = None
        self.work_queue = None
        self.work_directory = work_directory or os.path.join("usr", "share", "cb", "integrations", "%s" % self.name)
        self.database_file = os.path.join(self.work_directory, "sqlite.db")
        self._queue_initialized = False
        self.done = False
        self.feed_dirty = Event()
        self.feed_url = None
        self.feed_base_url = None
        self.link_base_url = None
        self.days_rescan = 365


        #
        # We need to reinitialize logging since we have forked
        #
        self.initialize_logging()

    ### Start: Functions which must be overriden in subclasses of DetonationDaemon ###

    @property
    def integration_name(self):
        return ''

    @property
    def num_quick_scan_threads(self):
        return 1

    @property
    def num_deep_scan_threads(self):
        return 5

    @property
    def filter_spec(self):
        return ''

    @property
    def historical_rate_limiter(self):
        return 0.5

    @property
    def up_to_date_rate_limiter(self):
        return 0.1

    def get_provider(self):
        raise IntegrationError("Integration did not provide a 'get_provider' function, which is required")

    def get_metadata(self):
        raise IntegrationError("Integration did not provide a 'get_metadata' function, which is required")

    ### End:   Functions which must be overriden in subclasses of DetonationDaemon ###

    def initialize_logging(self):
        if self.logfile is None:
            log_path = "/var/log/cb/integrations/%s/" % self.name
            cbint.utils.filesystem.ensure_directory_exists(log_path)
            self.logfile = "%s%s.log" % (log_path, self.name)

        rlh = RotatingFileHandler(self.logfile, maxBytes=524288, backupCount=10)
        rlh.setFormatter(logging.Formatter(fmt="%(asctime)s: %(module)s: %(levelname)s: %(message)s"))
        log.addHandler(rlh)

    def validate_config(self):
        if not self.cfg.has_section('bridge'):
            raise ConfigurationError("Configuration file does not have required section 'bridge'")

        self.check_required_options(['carbonblack_server_url', 'carbonblack_server_token'])

        ssl_verify = self.get_config_boolean("carbonblack_server_sslverify", False)
        server_url = self.cfg.get("bridge", "carbonblack_server_url")
        server_token = self.cfg.get("bridge", "carbonblack_server_token")

        #
        # There are times we need to wait for the Cb Response Server to be back up after a reboot.
        # So lets just sleep for 30 secs while we do 3 max retries
        #

        log.info(self.integration_name)

        cbinfo = None

        for i in range(3):
            try:
                self.cb = CbResponseAPI(url=server_url,
                                        token=server_token,
                                        ssl_verify=ssl_verify,
                                        integration_name=self.integration_name)
                cbinfo = self.cb.info()
                if cbinfo:
                    break
            except Exception as e:
                log.info(e.message)
                log.info("Failed to connect to Cb Response Server, retrying in 30 secs...")
                time.sleep(30)
                continue

        if not cbinfo:
            raise ConfigurationError("Could not connect to Cb server at %s" % (server_url))

        if self.get_config_boolean("use_streaming", False):
            self.check_required_options(['carbonblack_streaming_host', 'carbonblack_streaming_username',
                                         'carbonblack_streaming_password'])

            self.streaming_host = self.cfg.get('bridge', 'carbonblack_streaming_host')
            self.streaming_username = self.cfg.get('bridge', 'carbonblack_streaming_username')
            self.streaming_password = self.cfg.get('bridge', 'carbonblack_streaming_password')
            self.use_streaming = True
        else:
            self.use_streaming = False

        self.cert_file = self.get_config_string('cert_file')
        self.key_file = self.get_config_string('key_file')

        if self.key_file and self.cert_file:
            self.feed_base_url = "https://%s:%d" % (self.get_config_string('feed_host', '127.0.0.1'),
                                                   self.get_config_integer('listener_port', 8080))
        else:
            self.feed_base_url = "http://%s:%d" % (self.get_config_string('feed_host', '127.0.0.1'),
                                                   self.get_config_integer('listener_port', 8080))

        self.link_base_url = self.get_config_string('link_host_url')

        if not self.link_base_url:
            self.link_base_url = self.feed_base_url

        self.feed_url = "%s%s" % (self.feed_base_url, '/feed.json')

        if self.cfg.has_option('bridge', 'days_rescan'):
            self.days_rescan = self.get_config_integer('days_rescan', 365)

        return True

    def initialize_queue(self):
        if not self._queue_initialized:
            self.work_queue = SqliteQueue(self.database_file, num_days_before_rescan=self.days_rescan)
            self.work_queue.reprocess_on_restart()
            self._queue_initialized = True

        return self.work_queue

    def migrate_legacy_reports(self, legacy_directory):
        migrated_count = 0

        if not os.path.isdir(legacy_directory):
            log.info("Legacy directory %s doesn't exist, nothing to migrate" % legacy_directory)
            return migrated_count

        if os.path.isfile(os.path.join(legacy_directory, '.migrated')):
            log.info("Feed reports from %s already migrated" % legacy_directory)
            return migrated_count

        for fn in (f for f in os.listdir(legacy_directory) if os.path.isfile(os.path.join(legacy_directory,f))):
            try:
                d = json.load(open(os.path.join(legacy_directory, fn), 'rb'))
                short_result = d['title']
                timestamp = int(d['timestamp'])
                iocs = d['iocs']
                score = int(d['score'])
                link = d['link']

                # NOTE: we are assuming the first md5 in the list is the md5sum of the binary.
                md5_iocs = iocs.get('md5', [])
                if not md5_iocs:
                    log.warning("No MD5 IOCs in file %s" % fn)
                    continue

                md5sum = md5_iocs[0]
                md5_iocs.remove(md5sum)
                if not md5_iocs:
                    del(iocs['md5'])
                if not iocs:
                    iocs = None

                succeeded = (score >= 0)
            except Exception as e:
                log.warning("Could not parse file %s: %s" % (fn, e))
                continue

            try:
                if not self.work_queue.binary_exists_in_database(md5sum):
                    self.work_queue.append(md5sum)
                    self.work_queue.mark_as_analyzed(md5sum, succeeded, 0, short_result, '', score=score, link=link,
                                                     iocs=iocs)
                    migrated_count += 1
            except Exception as e:
                log.warning("Could not migrate file %s to new database: %s" % (fn, e))
                import traceback
                log.warning(traceback.format_exc())
                continue

            # try:
            #     os.remove(os.path.join(legacy_directory, fn))
            # except IOError:
            #     log.warning("Could not remove old file %s after migration: %s" % (fn, e))

        touch(os.path.join(legacy_directory, '.migrated'))

        log.info("Migrated %d reports from %s into database" % (migrated_count, legacy_directory))
        return migrated_count

    def start_binary_collectors(self, filter_spec):
        collectors = []
        now = datetime.datetime.utcnow()

        collectors.append(CbAPIHistoricalProducerThread(self.database_controller.register("producer"), self.cb, self.name,
                                                        sleep_between=self.get_config_integer('sleep_between_batches', 1200),
                                                        rate_limiter=self.historical_rate_limiter, start_time=now,
                                                        filter_spec=filter_spec)) # historical query
        collectors.append(CbAPIUpToDateProducerThread(self.database_controller.register("producer"), self.cb, self.name,
                                                      sleep_between=self.get_config_integer('sleep_between_batches', 30),
                                                      rate_limiter=self.up_to_date_rate_limiter, start_time=now,
                                                      filter_spec=filter_spec)) # constantly up-to-date query

        # if self.use_streaming:
        #     # TODO: need filter_spec for streaming
        #     collectors.append(CbStreamingProducerThread(self.database_controller.register("producer"), self.streaming_host, self.streaming_username,
        #                                                 self.streaming_password))

        for collector in collectors:
            collector.start()

        return collectors

    def start_feed_server(self, feed_metadata):
        self.feed_server = SqliteFeedServer(self.database_file,
                                            self.get_config_integer('listener_port', 8080),
                                            feed_metadata,
                                            self.link_base_url,
                                            self.work_directory,
                                            cert_file=self.cert_file,
                                            key_file=self.key_file,
                                            listener_address=self.get_config_string('listener_address', '0.0.0.0'))
        self.feed_server.start()

        #
        # With Cb Response 6.1, it is much faster to respond back to check if the feed exists.
        # So lets delay here a bit to make sure our feed server is running
        #
        for i in range(10):
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            result = sock.connect_ex((self.get_config_string('listener_address', '0.0.0.0'),
                                      self.get_config_integer('listener_port', 8080)))
            if result == 0:
                log.info("Feed server is running...")
                return
            else:
                log.info("Feed server isn't running yet, sleep for 5 seconds and trying again...")
            time.sleep(5)
        log.warning("Feed server doesn't seem to have started...")

    def get_or_create_feed(self, retry=3):

        feed_id = None

        for i in range(retry):
            try:
                feeds = get_object_by_name_or_id(self.cb, Feed, name=self.name)

                if not feeds:
                    log.info("Feed {} was not found, so we are going to create it".format(self.name))
                    break

                if len(feeds) > 1:
                    log.warning("Multiple feeds found, selecting Feed id {}".format(feeds[0].id))
                feed_id = feeds[0].id

                log.info("Feed {} was found as Feed ID {}".format(self.name, feed_id))
                break
            except Exception as e:
                log.info(e.message)
                break

        if not feed_id:
            log.info("Creating %s feed for the first time" % self.name)
            # TODO: clarification of feed_host vs listener_address

            f = self.cb.create(Feed)
            f.feed_url = self.feed_url
            f.enabled = True
            f.use_proxy = False
            f.validate_server_cert = False
            try:
                f.save()
            except ServerError as se:
                if se.error_code == 500:
                    log.info("Could not add feed:")
                    log.info(
                    " Received error code 500 from server. This is usually because the server cannot retrieve the feed.")
                    log.info(" Check to ensure the Cb server has network connectivity and the credentials are correct.")
                else:
                    log.info("Could not add feed: {0:s}".format(str(se)))
            except Exception as e:
                log.info("Could not add feed: {0:s}".format(str(e)))
            else:
                log.info("Feed data: {0:s}".format(str(f)))
                log.info("Added feed. New feed ID is {0:d}".format(f.id))
                feed_id = f.id

        return feed_id


    def run(self):
        try:
            work_queue = self.initialize_queue()
            self.database_controller = BinaryDatabaseController(work_queue)
            self.database_controller.start()

            # Import previous work, if enabled
            legacy_feed_directory = self.get_config_string("legacy_feed_directory", None)
            if legacy_feed_directory:
                self.migrate_legacy_reports(legacy_feed_directory)

            # Prepare binary analysis ("detonation") provider
            consumer_threads = []
            provider = self.get_provider()
            for i in range(self.num_quick_scan_threads):
                database_arbiter = self.database_controller.register("consumer", quick_scan=True)
                t = QuickScanThread(database_arbiter, self.cb, provider, dirty_event=self.feed_dirty)
                consumer_threads.append(t)
                t.start()
            for i in range(self.num_deep_scan_threads):
                database_arbiter = self.database_controller.register("consumer", quick_scan=False)
                t = DeepAnalysisThread(database_arbiter, self.cb, provider, dirty_event=self.feed_dirty)
                consumer_threads.append(t)
                t.start()

            # Start feed server
            metadata = self.get_metadata()
            self.start_feed_server(metadata)

            # Start collecting binaries
            collectors = self.start_binary_collectors(self.filter_spec)

            # Synchronize feed with Carbon Black
            self.get_or_create_feed()
            if cbint.utils.cbserver.is_server_at_least(self.cb, "4.1"):
                feed_synchronizer = FeedSyncRunner(self.cb, self.name, self.feed_dirty)
                feed_synchronizer.start()
        except Exception as e:
            log.error(e.message)

        try:
            while True:
                sleep(1)
        except KeyboardInterrupt:
            print 'stopping...'
            for t in consumer_threads + collectors:
                t.stop()
            for t in consumer_threads + collectors:
                t.join()
                print 'stopped %s' % t
