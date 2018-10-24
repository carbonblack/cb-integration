import logging
from datetime import datetime

logger = logging.getLogger(__name__)


class Statistics(object):
    def __init__(self):
        self.started = datetime.now()
        self.number_binaries_scanned = 0
        self.binaries_in_queue = 0
        self.number_binaries_db = 0
        self.last_error_message = None
        self.last_error_timestamp = None
        self.binaries_not_local = 0
        self.binaries_per_second = 0
        self.bd = None

    def to_dict(self):
        self.binaries_per_second = self.number_binaries_scanned / (datetime.now() - self.started).total_seconds()
        return {key: value for key, value in self.__dict__.items() if not key.startswith('__') and not callable(key)}


g_config = None
g_status = {}
g_volume_directory = "/"  # /conf/yara
g_base_directory = "/"  # /
g_statistics = Statistics()
g_integration = None
