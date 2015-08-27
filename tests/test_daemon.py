__author__ = 'jgarman'

import unittest
from cbint.utils.detonation import DetonationDaemon, CbAPIProducerThread
import os
import tempfile
import sys
import multiprocessing
import threading
import socket
from time import sleep

sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from utils.mock_server import get_mocked_server


class TestDaemon(DetonationDaemon):
    pass


class ServerNeverWokeUpError(Exception):
    pass


def sleep_till_available(conn_tuple):
    num_retries = 5
    while num_retries:
        s = socket.socket()
        try:
            s.connect(conn_tuple)
        except socket.error:
            num_retries -= 1
            sleep(.1)
        else:
            return

    raise ServerNeverWokeUpError(conn_tuple)


class DaemonTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        mydir = os.path.dirname(os.path.abspath(__file__))

        binaries_dir = os.path.join(mydir, 'data', 'binary_metadata')
        cls.mock_server = get_mocked_server(binaries_dir)
        cls.mock_server_thread = threading.Thread(target=cls.mock_server.run, args=['127.0.0.1', 7982])
        cls.mock_server_thread.daemon = True
        cls.mock_server_thread.start()
        sleep_till_available(('127.0.0.1', 7982))

    def setUp(self):
        self.temp_directory = tempfile.mkdtemp()
        config_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "daemon.conf")
        self.daemon = TestDaemon("testdaemon", configfile=config_path, work_directory=self.temp_directory,
                                 logfile=os.path.join(self.temp_directory, 'test.log'), debug=True)
        self.daemon.validate_config()

        self.daemon.initialize_queue()

    def tearDown(self):
        # os.rmdir(self.temp_directory)
        # self.mock_server_thread.terminate()
        pass

    def test_binary_collectors(self):
        CbAPIProducerThread(self.daemon.work_queue, self.daemon.cb, self.daemon.name, rate_limiter=0,
                            stop_when_done=True).run()
        cb_total = self.daemon.cb.binary_search('')['total_results']
        self.assertEquals(self.daemon.work_queue.number_unanalyzed(), cb_total)

    def test_empty(self):
        self.assertEquals(self.daemon.work_queue.number_unanalyzed(), 0)
