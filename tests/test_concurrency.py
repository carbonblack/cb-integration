__author__ = 'jgarman'


import threading
from time import sleep
import random
from cbint.utils.detonation.binary_queue import SqliteFeedServer, SqliteQueue
import datetime
import string
import unittest
import tempfile
import os


class ConsumerThread(threading.Thread):
    def __init__(self, work_queue):
        threading.Thread.__init__(self)
        self.queue = work_queue
        self.errors = []
        self.good = []

    def run(self):
        done = False
        while not done:
            md5sum = self.queue.get(sleep_wait=False)
            if not md5sum:
                done = True
                break

            print 'got md5sum %s' % md5sum
            # simulate processing
            sleep(random.random() * 0.05)
            if random.random() < 0.1:
                # we errored out!
                self.queue.mark_as_analyzed(md5sum, False, 1, "Error", "Longer error message",
                                            retry_at=datetime.datetime.now() + datetime.timedelta(seconds=10))
                print 'MARKED %s as error condition' % (md5sum,)
                self.errors.append(md5sum)
            else:
                self.queue.set_binary_available(md5sum)
                self.queue.mark_as_analyzed(md5sum, True, 1, "bad stuff happened", "whoa", score=100)
                self.good.append(md5sum)


class ProducerThread(threading.Thread):
    def __init__(self, work_queue, number_items):
        threading.Thread.__init__(self)
        self.queue = work_queue
        self.produced = []
        self.number_items = number_items

    def run(self):
        for i in xrange(self.number_items):
            md5sum = ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(32))
            self.queue.append(md5sum)
            self.produced.append(md5sum)


class ConcurrencyTestCase(unittest.TestCase):
    def setUp(self):
        with tempfile.NamedTemporaryFile(delete=False) as fn:
            self.filename = fn.name
            self.work_queue = SqliteQueue(self.filename)

    def tearDown(self):
        os.unlink(self.filename)

    def test_concurrency(self):
        producer_threads = []
        consumer_threads = []

        self.work_queue.reprocess_on_restart() # handle things that were in-process when we died

        for i in range(10):
            producer_threads.append(ProducerThread(self.work_queue, 20))

        for t in producer_threads:
            t.start()

        sleep(0.1)

        for i in range(5):
            consumer_threads.append(ConsumerThread(self.work_queue))

        for t in consumer_threads:
            t.start()

        for t in producer_threads:
            t.join()
        for t in consumer_threads:
            t.join()

        md5s_produced = []
        md5s_consumed = []
        for t in producer_threads:
            md5s_produced.extend(t.produced)


        for t in consumer_threads:
            md5s_consumed.extend(t.errors)
            md5s_consumed.extend(t.good)

        return set(md5s_produced) == set(md5s_consumed)
