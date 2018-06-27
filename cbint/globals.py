import json

class Statistics(object):
    def init(self):
        self.number_binaries_scanned = 0
        self.binaries_in_queue = 0
        self.number_binaries_db = 0
        self.last_error_message = ""
        self.last_error_timestamp = ""
        self.binaries_not_local = 0

    def __str__(self):
        return json.dumps([a for a in dir(self) if not a.startswith('__')])

g_config = None
g_status = {}
g_volume_directory = "/" # /conf/yara
g_base_directory = "/" # /
g_statistics = Statistics()




