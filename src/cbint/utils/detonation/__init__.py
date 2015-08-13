__author__ = 'jgarman'

from cbint.utils.daemon import CbIntegrationDaemon, ConfigurationError
from cbint.utils.detonation.binary_queue import SqliteQueue, SqliteFeedServer
from cbint.utils.detonation.binary_analysis import CbAPIProducerThread, CbStreamingProducerThread
import cbapi
import os.path


class DetonationDaemon(CbIntegrationDaemon):
    def __init__(self, name, **kwargs):
        work_directory = kwargs.pop('work_directory', None)
        CbIntegrationDaemon.__init__(self, name, **kwargs)
        self.cb = None
        self.work_queue = None
        self.work_directory = work_directory or os.path.join("usr", "share", "cb", "integrations", "%s" % self.name)
        self.database_file = os.path.join(self.work_directory, "sqlite.db")

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
        server_url = self.cfg.get_option("bridge", "carbonblack_server_url")
        server_token = self.cfg.get_option("bridge", "carbonblack_server_token")
        try:
            self.cb = cbapi.CbApi(server_url, token=server_token, ssl_verify=ssl_verify)
        except Exception as e:
            raise ConfigurationError("Could not create CbAPI instance to %s: %s" % (server_url, e.message))

        if self.get_config_boolean("use_streaming", False):
            self.check_required_options(['carbonblack_streaming_host', 'carbonblack_streaming_username',
                                         'carbonblack_streaming_password'])

            self.streaming_host = self.cfg.get_option('bridge', 'carbonblack_streaming_host')
            self.streaming_username = self.cfg.get_option('bridge', 'carbonblack_streaming_username')
            self.streaming_password = self.cfg.get_option('bridge', 'carbonblack_streaming_password')
            self.use_streaming = True
        else:
            self.use_streaming = False

    def initialize_queue(self):
        self.work_queue = SqliteQueue(self.database_file)
        self.work_queue.reprocess_on_restart()

        # TODO: check to see if there are existing files that we should import from a previous version of the connector

        self.feed_server = SqliteFeedServer(self.database_file)
        self.feed_server.start()

        return self.work_queue

    def start_binary_collectors(self):
        CbAPIProducerThread(self.work_queue, self.cb, self.name, sleep_between=10).start()                # historical query
        CbAPIProducerThread(self.work_queue, self.cb, self.name, max_rows=100, sleep_between=10).start()  # constantly up-to-date query
        if self.use_streaming:
            CbStreamingProducerThread(self.work_queue, self.streaming_host, self.streaming_username,
                                      self.streaming_password).start()
