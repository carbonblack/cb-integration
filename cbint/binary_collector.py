import threading
import time
import logging

from cbapi.response.models import Binary
from cbint.binary_database import BinaryDetonationResult

logger = logging.getLogger(__name__)


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
        binary_query = self.cb.select(Binary).where(self.query)
        self.total_results = len(binary_query)

        for binary in binary_query:
            if self.terminate:
                break
            det = BinaryDetonationResult()
            det.md5 = binary.md5
            #
            # Save into database
            #
            det.save()
            time.sleep(self.sleep_interval)
