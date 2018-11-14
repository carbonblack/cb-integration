import datetime
import logging
import threading
import time
import traceback
from datetime import datetime, timedelta

from cbapi.response.models import Binary as CbrBinary
from cbapi.response.rest_api import CbResponseAPI
from dateutil import parser

import cbint.globals
from cbint.binary_database import BinaryDetonationResult,db
from multiprocessing.pool import ThreadPool
from peewee import chunked 


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
        #self.pool = ThreadPool()

    def get_newest_binary_date(self):
          results = BinaryDetonationResult().select().order_by(BinaryDetonationResult.server_added_timestamp.desc(),
                                                                 BinaryDetonationResult.from_rabbitmq.desc()).limit(1)
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

        current_datetime = None
        while True:
            try:
                if current_datetime is None:
                    newest_binary_date = self.get_newest_binary_date()
                    if newest_binary_date:
                        current_datetime = parser.parse(newest_binary_date)

                query = self.query
                if current_datetime:
                    #
                    # Keep this for postgres
                    # datetime_object = newest_binary_date
                    #
                    query += " server_added_timestamp:[{0} TO *]".format(convert_to_cb(current_datetime))

                binary_query = self.cb.select(CbrBinary).where(query).sort("server_added_timestamp asc")

                if len(binary_query) == 0:
                    time.sleep(30)
                    continue

                #prepare data for blunk async insertion
                data = ((bin.md5,bin.server_added_timestamp) for bin in binary_query)
                for chunk in chunked(data,999):
                    BinaryDetonationResult.insert_many(chunk,fields=[BinaryDetonationResult.md5,BinaryDetonationResult.server_added_timestamp]).execute()
                current_datetime = parser.parse(binary_query[-1].server_added_timestamp)
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
