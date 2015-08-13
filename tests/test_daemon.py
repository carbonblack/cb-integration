__author__ = 'jgarman'

import unittest
from cbint.utils.detonation import DetonationDaemon
import os
import tempfile
import sys

sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from utils.mock_server import MockServer, get_carbon_black_handler


class TestDaemon(DetonationDaemon):
    pass


class DaemonTest(unittest.TestCase):
    def setUp(self):
        self.temp_directory = tempfile.mkdtemp()
        config_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "daemon.conf")
        self.daemon = TestDaemon("testdaemon", configfile=config_path, work_directory=self.temp_directory,
                                 logfile=os.path.join(self.temp_directory, 'test.log'), debug=True)
        self.mock_cb_server = MockServer(7982, get_carbon_black_handler(self.temp_directory))

    def tearDown(self):
        # os.rmdir(self.temp_directory)
        pass

    def test_daemon_queue(self):
        self.daemon.initialize_queue()

    def test_binary_collectors(self):
        pass