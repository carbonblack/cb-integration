import datetime
import logging
import threading
import time
import traceback
from datetime import datetime

from cbapi.response.models import Binary as CbrBinary
from cbapi.response.rest_api import CbResponseAPI
from dateutil import parser

import cbint.globals
from cbint.binary_database import Binary

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

cb_datetime_format = "%Y-%m-%dT%H:%M:%S"

PAGE_SIZE = 1000


def convert_to_cb(dt):
    return dt.strftime(cb_datetime_format)


class BinaryCollector(threading.Thread):
    def __init__(self, query, queue, sleep_interval=.1):
        threading.Thread.__init__(self)
        self.binary_queue = queue
        self.query = query
        self.sleep_interval = sleep_interval
        self.total_results = 0
        self.current_index = 0
        self.terminate = False
        self.binary_time = datetime.now()
        self.cb = CbResponseAPI(url=cbint.globals.g_config.get("carbonblack_server_url"),
                                token=cbint.globals.g_config.get("carbonblack_server_token"),
                                ssl_verify=cbint.globals.g_config.getboolean("carbonblack_server_sslverify"))

    def get_newest_binary_date(self):
        results = Binary().select().where(Binary.from_rabbitmq == False) \
            .order_by(Binary.server_added_timestamp.desc()).limit(1)
        if not results:
            return None
        else:
            return results[0].server_added_timestamp

    def get_oldest_binary_date(self):
        results = Binary() \
            .select() \
            .order_by(Binary.server_added_timestamp.asc())
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

                logger.info("binary_collector newest_binary_date: {0}".format(newest_binary_date))

                query = self.query
                if newest_binary_date:
                    datetime_object = parser.parse(newest_binary_date)
                    #
                    # Keep this for postgres
                    # datetime_object = newest_binary_date
                    #
                    query += " server_added_timestamp:[{0} TO *]".format(convert_to_cb(datetime_object))

                binary_query = self.cb.select(CbrBinary).where(query).sort("server_added_timestamp asc")
                binary_query._batch_size = PAGE_SIZE

                if len(binary_query) == 0:
                    time.sleep(30)
                    continue

                for binary in binary_query[:PAGE_SIZE]:
                    if self.terminate:
                        break

                    exist_query = Binary.select().where(Binary.md5 == binary.md5)
                    if exist_query.exists():
                        logger.info("binary already exists in database: {0}".format(binary.md5))
                        time.sleep(self.sleep_interval)
                        continue

                    try:
                        bin = Binary()
                        bin.md5 = binary.md5
                        bin.server_added_timestamp = binary.server_added_timestamp
                        bin.save()
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
