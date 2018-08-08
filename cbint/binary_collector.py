import datetime
import logging
import threading
import time
import traceback
from datetime import datetime

from cbapi.response.models import Binary
from cbapi.response.rest_api import CbResponseAPI
from dateutil import parser

import cbint.globals
from cbint.binary_database import BinaryDetonationResult

logger = logging.getLogger(__name__)

cb_datetime_format = "%Y-%m-%dT%H:%M:%S"

PAGE_SIZE = 1000


def convert_to_cb(dt):
    return dt.strftime(cb_datetime_format)


class BinaryCollector(threading.Thread):
    def __init__(self, query, sleep_interval=.1):
        threading.Thread.__init__(self)
        self.query = query
        self.sleep_interval = sleep_interval
        self.total_results = 0
        self.current_index = 0
        self.terminate = False
        self.binary_time = datetime.now()

    def get_newest_binary_date(self):
        results = BinaryDetonationResult().select().order_by(BinaryDetonationResult.server_added_timestamp.desc())
        if not results:
            return None
        else:
            return results[0].server_added_timestamp

    def get_oldest_binary_date(self):
        results = BinaryDetonationResult() \
            .select() \
            .order_by(BinaryDetonationResult.server_added_timestamp.asc())
        if not results:
            return None
        else:
            return results[0].server_added_timestamp

    def stop(self):
        self.terminate = True

    def collect_oldest_newest_binaries(self):
        while True:
            try:
                #
                # Get the newest binary we have in the sqlite db
                #
                newest_binary_date = self.get_newest_binary_date()

                query = self.query
                if newest_binary_date:
                    datetime_object = parser.parse(newest_binary_date)
                    query += " server_added_timestamp:[{0} TO *]".format(convert_to_cb(datetime_object))

                self.cb = CbResponseAPI(url=cbint.globals.g_config.get("carbonblack_server_url"),
                                        token=cbint.globals.g_config.get("carbonblack_server_token"),
                                        ssl_verify=cbint.globals.g_config.getboolean("carbonblack_server_sslverify"))

                binary_query = self.cb.select(Binary).where(query).sort("server_added_timestamp asc")
                binary_query._batch_size = PAGE_SIZE

                if len(binary_query) == 0:
                    time.sleep(self.sleep_interval)
                    continue

                for binary in binary_query[:PAGE_SIZE]:
                    if self.terminate:
                        break

                    exist_query = BinaryDetonationResult.select().where(BinaryDetonationResult.md5 == binary.md5)
                    if exist_query.exists():
                        continue

                    try:
                        det = BinaryDetonationResult()
                        det.md5 = binary.md5
                        det.server_added_timestamp = binary.server_added_timestamp

                        #
                        # Save into database
                        #
                        det.save()
                        time.sleep(self.sleep_interval)
                    except Exception as e:
                        logger.error(traceback.format_exc())
                        continue

                if self.terminate:
                    break
            except:
                logger.error(traceback.format_exc())
            time.sleep(self.sleep_interval)

    def run(self):
        while True:
            try:
                self.collect_oldest_newest_binaries()
            except Exception as e:
                logger.error(traceback.format_exc())
            time.sleep(self.sleep_interval)
