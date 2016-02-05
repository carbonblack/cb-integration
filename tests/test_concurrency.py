__author__ = 'jgarman'


import threading
from time import sleep
import random
from cbint.utils.detonation.binary_queue import SqliteFeedServer, SqliteQueue, BinaryDatabaseArbiter, BinaryDatabaseController
import datetime
import string
import unittest
import tempfile
import os

import logging
logging.basicConfig(level=logging.DEBUG)


class ConsumerThread(threading.Thread):
    def __init__(self, arbiter):
        threading.Thread.__init__(self)
        self.daemon = True

        self.arbiter = arbiter
        self.errors = []
        self.good = []

    def run(self):
        for md5sum in self.arbiter.binaries():
            # simulate processing
            sleep(random.random() * 0.05)
            if random.random() < 0.1:
                # we errored out!
                self.arbiter.mark_as_analyzed(md5sum, False, 1, "Error", "Longer error message",
                                              retry_at=datetime.datetime.now() + datetime.timedelta(seconds=10))
                self.errors.append(md5sum)
            else:
                self.arbiter.set_binary_available(md5sum)
                self.arbiter.mark_as_analyzed(md5sum, True, 1, "bad stuff happened", "whoa", score=100)
                self.good.append(md5sum)


class ProducerThread(threading.Thread):
    def __init__(self, arbiter, number_items):
        threading.Thread.__init__(self)
        self.daemon = True

        self.arbiter = arbiter
        self.produced = []
        self.number_items = number_items

    def run(self):
        for i in xrange(self.number_items):
            md5sum = ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(32))
            self.arbiter.notify_binary_available(md5sum)
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
        db_controller = BinaryDatabaseController(self.work_queue)
        db_controller.start()

        for i in range(10):
            producer_threads.append(ProducerThread(db_controller.register("producer"), 20))

        for t in producer_threads:
            t.start()

        sleep(0.1)

        for i in range(5):
            consumer_threads.append(ConsumerThread(db_controller.register("consumer")))

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

        self.assertSetEqual(set(md5s_produced), set(md5s_consumed))
