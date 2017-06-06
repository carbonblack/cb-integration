from cbint.utils.detonation import DetonationDaemon
from cbint.utils.detonation.binary_analysis import (BinaryAnalysisProvider, AnalysisResult)
import cbint.utils.feed
import cbint.utils.flaskfeed
import logging

import os
from flask import jsonify
import threading
import sys

log = logging.getLogger(__name__)

class TestProvider(BinaryAnalysisProvider):
    def __init__(self, name):
        super(TestProvider, self).__init__(name)

    def check_result_for(self, md5sum):
        log.info("Quick Scanning {}".format(md5sum))
        return None

    def analyze_binary(self, md5sum, binary_file_stream):
        log.info("Deep Scanning {}".format(md5sum))
        return AnalysisResult(score=0)


class TestConnector(DetonationDaemon):

    @property
    def integration_name(self):
        return 'Test Connector 1.3.0'

    @property
    def num_quick_scan_threads(self):
        return 2

    @property
    def num_deep_scan_threads(self):
        return 2

    @property
    def up_to_date_rate_limiter(self):
        return 0

    @property
    def historical_rate_limiter(self):
        return 0

    def get_provider(self):
        test_provider = TestProvider("testprovider")
        return test_provider

    def get_metadata(self):
        return cbint.utils.feed.generate_feed(self.name,
                                              summary="TestConnector",
                                              tech_data="There are no requirements to share any data with Carbon Black to use this feed.",
                                              provider_url="http://plusvic.github.io/yara/",
                                              icon_path='/usr/share/cb/integrations/yara/yara-logo.png',
                                              display_name="TestConnector",
                                              category="Connectors")

def handle_index_request():
    return jsonify({})


class FuncThread(threading.Thread):
    def __init__(self, target, *args):
        self._target = target
        self._args = args
        threading.Thread.__init__(self)

    def run(self):
        self._target(*self._args)


if __name__ == '__main__':
    import logging
    logging.basicConfig(level=logging.DEBUG)
    stdout_hdlr = logging.StreamHandler(sys.stdout)
    log.addHandler(stdout_hdlr)

    my_path = os.path.dirname(os.path.abspath(__file__))
    temp_directory = "/tmp"

    #two_way_feed = cbint.utils.flaskfeed.FlaskFeed("twowaytest", cert_file="/tmp/server.crt", key_file="/tmp/server.nopass.key")
    #two_way_feed.app.add_url_rule("/", view_func=handle_index_request, methods=['GET'])

    #t1 = FuncThread(two_way_feed.run, "0.0.0.0", 8080, False)
    #log.info("starting...")
    #t1.start()
    #log.info("after starting...")

    config_path = os.path.join(my_path, "devel_daemon.conf")
    daemon = TestConnector('testconnector',
                           configfile=config_path,
                           work_directory=temp_directory,
                           logfile=os.path.join(temp_directory, 'test.log'))
    daemon.validate_config()
    daemon.start()

