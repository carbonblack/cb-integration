__author__ = 'jgarman'

from cbint.utils.daemon import CbIntegrationDaemon, ConfigurationError
from cbint.utils.detonation.binary_queue import SqliteQueue, SqliteFeedServer
from cbint.utils.detonation.binary_analysis import (CbAPIProducerThread, CbStreamingProducerThread, QuickScanThread,
                                                    DeepAnalysisThread)
import cbint.utils.feed
import cbint.utils.cbserver
import cbapi
import os.path
from threading import Event, Thread
from time import sleep
import logging

try:
    import simplejson as json
except ImportError:
    import json


log = logging.getLogger(__name__)


class IntegrationError(Exception):
    pass


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
                logging.info("synchronizing feed: %s" % self.__feed_name)
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

    ### Start: Functions which must be overriden in subclasses of DetonationDaemon ###

    @property
    def num_quick_scan_threads(self):
        return 1

    @property
    def num_deep_scan_threads(self):
        return 5

    @property
    def filter_spec(self):
        return ''

    def get_provider(self):
        raise IntegrationError("Integration did not provide a 'get_provider' function, which is required")

    def get_metadata(self):
        raise IntegrationError("Integration did not provide a 'get_metadata' function, which is required")

    ### End:   Functions which must be overriden in subclasses of DetonationDaemon ###

    def get_config_string(self, config_key, default_value=None):
        if self.cfg.has_option("bridge", config_key):
            return self.cfg.get("bridge", config_key)
        else:
            return default_value

    def get_config_boolean(self, config_key, default_value=False):
        if self.cfg.has_option("bridge", config_key):
            return self.cfg.getboolean("bridge", config_key)
        else:
            return default_value

    def get_config_integer(self, config_key, default_value=0):
        if self.cfg.has_option("bridge", config_key):
            return self.cfg.getint("bridge", config_key)
        else:
            return default_value

    def check_required_options(self, required_options):
        for option in required_options:
            if not self.cfg.has_option("bridge", option):
                raise ConfigurationError("Configuration file does not have required option %s in [bridge] section" %
                                         option)

    def validate_config(self):
        if not self.cfg.has_section('bridge'):
            raise ConfigurationError("Configuration file does not have required section 'bridge'")

        self.check_required_options(['carbonblack_server_url', 'carbonblack_server_token'])

        ssl_verify = self.get_config_boolean("carbonblack_server_sslverify", False)
        server_url = self.cfg.get("bridge", "carbonblack_server_url")
        server_token = self.cfg.get("bridge", "carbonblack_server_token")
        try:
            self.cb = cbapi.CbApi(server_url, token=server_token, ssl_verify=ssl_verify)
        except Exception as e:
            raise ConfigurationError("Could not create CbAPI instance to %s: %s" % (server_url, e.message))

        if self.get_config_boolean("use_streaming", False):
            self.check_required_options(['carbonblack_streaming_host', 'carbonblack_streaming_username',
                                         'carbonblack_streaming_password'])

            self.streaming_host = self.cfg.get('bridge', 'carbonblack_streaming_host')
            self.streaming_username = self.cfg.get('bridge', 'carbonblack_streaming_username')
            self.streaming_password = self.cfg.get('bridge', 'carbonblack_streaming_password')
            self.use_streaming = True
        else:
            self.use_streaming = False

        self.feed_url = "http://%s:%d%s" % (self.get_config_string('feed_host', '127.0.0.1'),
                                                                   self.get_config_integer('listener_port', 8080),
                                                                   '/feed.json')

        return True

    def initialize_queue(self):
        if not self._queue_initialized:
            self.work_queue = SqliteQueue(self.database_file)
            self.work_queue.reprocess_on_restart()
            self._queue_initialized = True

        return self.work_queue

    def migrate_legacy_reports(self, legacy_directory):
        migrated_count = 0

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

            try:
                os.remove(os.path.join(legacy_directory, fn))
            except IOError:
                log.warning("Could not remove old file %s after migration: %s" % (fn, e))

        log.info("Migrated %d reports into database" % migrated_count)

    def start_binary_collectors(self, filter_spec):
        collectors = []

        collectors.append(CbAPIProducerThread(self.work_queue, self.cb, self.name,
                                              sleep_between=10, filter_spec=filter_spec)) # historical query
        collectors.append(CbAPIProducerThread(self.work_queue, self.cb, self.name,
                                              max_rows=100, sleep_between=10, filter_spec=filter_spec))
            # constantly up-to-date query

        if self.use_streaming:
            # TODO: need filter_spec for streaming
            collectors.append(CbStreamingProducerThread(self.work_queue, self.streaming_host, self.streaming_username,
                                      self.streaming_password))

        for collector in collectors:
            collector.start()

        return collectors

    def start_feed_server(self, feed_metadata):
        self.feed_server = SqliteFeedServer(self.database_file, self.get_config_integer('listener_port', 8080),
                                            feed_metadata,
                                            listener_address=self.get_config_string('listener_address', '0.0.0.0'))
        self.feed_server.start()

    def get_or_create_feed(self):
        feed_id = self.cb.feed_get_id_by_name(self.name)
        self.logger.info("Feed id for %s: %s" % (self.name, feed_id))
        if not feed_id:
            self.logger.info("Creating %s feed for the first time" % self.name)
            # TODO: clarification of feed_host vs listener_address
            result = self.cb.feed_add_from_url(self.feed_url, True, False, False)

            # TODO: defensive coding around these self.cb calls
            feed_id = result.get('id', 0)

        return feed_id

    def run(self):
        work_queue = self.initialize_queue()

        # Prepare binary analysis ("detonation") provider
        consumer_threads = []
        provider = self.get_provider()
        for i in range(self.num_quick_scan_threads):
            t = QuickScanThread(work_queue, self.cb, provider, dirty_event=self.feed_dirty)
            consumer_threads.append(t)
            t.start()
        for i in range(self.num_deep_scan_threads):
            t = DeepAnalysisThread(work_queue, self.cb, provider, dirty_event=self.feed_dirty)
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
