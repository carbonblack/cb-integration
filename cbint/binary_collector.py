import threading
import time
import logging
import traceback
import datetime
from datetime import datetime
from dateutil import parser

from cbapi.response.models import Binary
from cbint.binary_database import BinaryDetonationResult

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

cb_datetime_format = "%Y-%m-%dT%H:%M:%S"

PAGE_SIZE = 1000


def convert_to_cb(dt):
    return dt.strftime(cb_datetime_format)


class BinaryCollector(threading.Thread):
    def __init__(self, cb, query, sleep_interval=.1):
        threading.Thread.__init__(self)
        self.cb = cb
        self.query = query
        self.sleep_interval = sleep_interval
        self.total_results = 0
        self.current_index = 0
        self.terminate = False
        self.binary_time = datetime.now()

    def get_newest_binary_date(self):
        results = BinaryDetonationResult().select().order_by(BinaryDetonationResult.server_added_timestamp.asc())
        if not results:
            return None
        else:
            return results[0].server_added_timestamp

    def get_oldest_binary_date(self):
        results = BinaryDetonationResult().select().order_by(BinaryDetonationResult.server_added_timestamp.desc())
        if not results:
            return None
        else:
            return results[0].server_added_timestamp

    def stop(self):
        self.terminate = True

    def collect_oldest_newest_binaries(self):
        while True:
            #
            # Get the oldest binary we have in the sqlite db
            #
            oldest_binary_date = self.get_oldest_binary_date()

            query = ""
            if oldest_binary_date:
                datetime_object = dt = parser.parse(oldest_binary_date)
                query = "server_added_timestamp:[{0} TO *]".format(convert_to_cb(datetime_object))

            binary_query = self.cb.select(Binary).where(query).sort("server_added_timestamp asc")
            binary_query._batch_size = PAGE_SIZE

            if len(binary_query) == 0:
                time.sleep(self.sleep_interval)
                continue

            for binary in binary_query[:PAGE_SIZE]:
                if self.terminate:
                    break

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

    # def collect_newer_binaries(self):
    #     while True:
    #         #
    #         # Get the oldest binary we have in the sqlite db
    #         #
    #         newest_binary_date = self.get_newest_binary_date()
    #
    #         query = ""
    #         if newest_binary_date:
    #             query = "server_added_timestamp:[{0} TO *]".format(convert_to_cb(newest_binary_date))
    #
    #         binary_query = self.cb.select(Binary).where(query).sort("server_added_timestamp asc")
    #         binary_query._batch_size = PAGE_SIZE
    #
    #         if len(binary_query) == 0:
    #             continue
    #
    #         for binary in binary_query[:PAGE_SIZE]:
    #             if self.terminate:
    #                 break
    #
    #             try:
    #                 det = BinaryDetonationResult()
    #                 det.md5 = binary.md5
    #                 det.server_added_timestamp = binary.server_added_timestamp
    #                 #
    #                 # Save into database
    #                 #
    #                 det.save()
    #                 time.sleep(self.sleep_interval)
    #             except Exception as e:
    #                 logger.error(traceback.format_exc())
    #                 continue
    #
    #         if self.terminate:
    #             break
    #
    # def collect_older_binaries(self):
    #     while True:
    #         #
    #         # Get the oldest binary we have in the sqlite db
    #         #
    #         oldest_binary_date = self.get_oldest_binary_date()
    #
    #         query = ""
    #         if oldest_binary_date:
    #             query = "server_added_timestamp:[* TO {0}]".format(convert_to_cb(oldest_binary_date))
    #
    #         binary_query = self.cb.select(Binary).where(query).sort("server_added_timestamp desc")
    #         binary_query._batch_size = PAGE_SIZE
    #
    #         if len(binary_query) == 0:
    #             return
    #
    #         for binary in binary_query[:PAGE_SIZE]:
    #             if self.terminate:
    #                 break
    #
    #             try:
    #                 det = BinaryDetonationResult()
    #                 det.md5 = binary.md5
    #                 det.server_added_timestamp = binary.server_added_timestamp
    #                 #
    #                 # Save into database
    #                 #
    #                 det.save()
    #                 time.sleep(self.sleep_interval)
    #             except Exception as e:
    #                 logger.error(traceback.format_exc())
    #                 continue
    #
    #         if self.terminate:
    #             break

    def run(self):
        while True:
            try:
                self.collect_oldest_newest_binaries()
                time.sleep(self.sleep_interval)
            except Exception as e:
                logger.error(traceback.format_exc())
