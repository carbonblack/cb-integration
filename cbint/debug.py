import cbint.globals
from datetime import datetime

def report_error(error_msg):
    cbint.globals.g_statistics.last_error_message = error_msg
    cbint.globals.g_statistics.last_error_timestamp = datetime.now()