import json


class Statistics(object):
    number_binaries_scanned = 0
    binaries_in_queue = 0
    number_binaries_db = 0
    last_error_message = None
    last_error_timestamp = None
    binaries_not_local = 0

    def __str__(self):
        return json.dumps([a for a in dir(self) if not a.startswith('__')])


g_config = None
g_status = {}
g_volume_directory = "/"  # /conf/yara
g_base_directory = "/"  # /
g_statistics = Statistics()
