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

    @property
    def num_quick_scan_threads(self):
        return 1

    @property
    def num_deep_scan_threads(self):
        return 5

    def get_provider(self):
        raise IntegrationError("Integration did not provide a 'get_provider' function, which is required")

    def get_metadata(self):
        raise IntegrationError("Integration did not provide a 'get_metadata' function, which is required")

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
            return self.cfg.getinteger("bridge", config_key)
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

            # TODO: check to see if there are existing files that we should import from a previous version of the connector
            self._queue_initialized = True

        return self.work_queue

    def start_binary_collectors(self):
        CbAPIProducerThread(self.work_queue, self.cb, self.name, sleep_between=10).start()                # historical query
        CbAPIProducerThread(self.work_queue, self.cb, self.name, max_rows=100, sleep_between=10).start()  # constantly up-to-date query
        if self.use_streaming:
            CbStreamingProducerThread(self.work_queue, self.streaming_host, self.streaming_username,
                                      self.streaming_password).start()

    def start_feed_server(self, feed_metadata):
        self.feed_server = SqliteFeedServer(self.database_file, self.get_config_integer('listener_port', 8080),
                                            feed_metadata)
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
        self.start_binary_collectors()

        # Synchronize feed with Carbon Black
        self.get_or_create_feed()
        if cbint.utils.cbserver.is_server_at_least(self.cb, "4.1"):
            feed_synchronizer = FeedSyncRunner(self.cb, self.name, self.feed_dirty)
            feed_synchronizer.start()
