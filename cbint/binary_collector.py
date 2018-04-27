import threading
import time
import logging
import traceback

from cbapi.response.models import Binary

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)


class BinaryCollector(threading.Thread):
    def __init__(self, cb, query, sleep_interval=.1):
        threading.Thread.__init__(self)
        self.cb = cb
        self.query = query
        self.sleep_interval = sleep_interval
        self.total_results = 0
        self.current_index = 0
        self.terminate = False


    def stop(self):
        self.terminate = True

    def run(self):
        from cbint.binary_database import BinaryDetonationResult
        binary_query = self.cb.select(Binary).where(self.query)
        self.total_results = len(binary_query)

        for binary in binary_query:
            if self.terminate:
                break
            try:
                det = BinaryDetonationResult()
                det.md5 = binary.md5
                #
                # Save into database
                #
                det.save()
                time.sleep(self.sleep_interval)
            except Exception as e:
                logger.info(traceback.format_exc())
                continue
