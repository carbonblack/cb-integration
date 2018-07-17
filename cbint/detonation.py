import logging
import time
import threading
import traceback
import base64
import cbint.globals
import os
import queue
from datetime import datetime, timedelta

from cbint.analysis import AnalysisResult
from cbint.integration import Integration
from cbint.binary_database import db
from cbint.binary_database import BinaryDetonationResult
from cbint.binary_collector import BinaryCollector
from cbapi.response.rest_api import CbResponseAPI
from cbapi.response.models import Binary
from cbapi.errors import *

from cbint.cbfeeds import CbReport, CbFeed

from cbint.utils.helpers import report_error_statistics

from cbint.flask_feed import app

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

BINARY_QUEUE_MAX_SIZE = 100


class BinaryDetonation(Integration):
    def __init__(self, name=""):
        super().__init__(name=name)
        self.binary_queue = queue.Queue(maxsize=BINARY_QUEUE_MAX_SIZE)

        #
        # Connect to the sqlite db and make sure the tables are created
        #

        logger.debug("Attempting to connect to sqlite database...")
        try:
            db.init(os.path.join(cbint.globals.g_volume_directory, self.name, "db", "binary.db"))
            logger.debug("Binary Db Path: {0}".format(
                os.path.join(cbint.globals.g_volume_directory, self.name, "db", "binary.db")))
            db.start()
            db.connect()
            db.create_tables([BinaryDetonationResult])
            self.db_object = db
        except Exception as e:
            logger.error(traceback.format_exc())
            report_error_statistics(str(e))

        time.sleep(1)
        logger.debug("Connected to sqlite database")

        #
        # Create a Binary Collector and start it
        #
        logger.debug("Starting binary collector...")
        bc = BinaryCollector(query=cbint.globals.g_config.get("binary_filter_query"))
        bc.start()
        self.binary_collector = bc
        logger.debug("Binary Collector has started")

        self.flask_feed = app
        self.flask_thread = threading.Thread(target=self.flask_feed.run,
                                             kwargs={"host": "127.0.0.1",
                                                     "port": cbint.globals.g_config.getint('listener_port', 8080),
                                                     "debug": False,
                                                     "use_reloader": False})

        self.flask_thread.daemon = True
        self.flask_thread.start()

        self.db_inserter_thread = threading.Thread(target=self.insert_binaries_from_db)
        self.db_inserter_thread.daemon = True
        self.db_inserter_thread.start()

        logger.debug("init complete")

    def set_feed_info(self,
                      name,
                      summary='',
                      tech_data='',
                      provider_url='',
                      icon_path='',
                      display_name=''):
        """
        :param name:
        :param summary:
        :param tech_data:
        :param provider_url:
        :param icon_path:
        :param display_name:
        :return:
        """
        icon = base64.b64encode(open(icon_path, 'rb').read()).decode('utf-8')

        self.feedinfo = {"name": name,
                         "summary": summary,
                         "tech_data": tech_data,
                         "provider_url": provider_url,
                         "icon": icon,
                         "display_name": display_name}

    def binaries_to_scan(self):

        while True:
            binary = self.binary_queue.get(block=True, timeout=None)
            self.binary_queue.task_done()
            if not binary:
                continue
            yield binary

    def get_possible_alliance_binary(self):
        while True:
            #
            # Get all binaries we have tried to scan, but could NOT download and we last tried 1 day ago
            #
            results = BinaryDetonationResult.select() \
                .where(BinaryDetonationResult.binary_not_available == True) \
                .where(BinaryDetonationResult.last_scan_attempt < datetime.today() - timedelta(days=1)) \
                .order_by(BinaryDetonationResult.last_scan_attempt.asc()) \
                .limit(100)
            if not results:
                return
            for result in results:
                yield result

    def download_binary_insert_queue(self, binary_db_entry):
        md5 = binary_db_entry.md5
        cb = CbResponseAPI(url=cbint.globals.g_config.get("carbonblack_server_url"),
                           token=cbint.globals.g_config.get("carbonblack_server_token"),
                           ssl_verify=cbint.globals.g_config.getboolean("carbonblack_server_sslverify"))
        binary_query = cb.select(Binary).where(f"md5:{md5}")
        if binary_query:
            try:
                binary_query[0].file.read()
            except ObjectNotFoundError:
                binary_db_entry.binary_not_available = True
                binary_db_entry.server_added_timestamp = binary_query[0].server_added_timestamp
                binary_db_entry.num_attempts += 1
                binary_db_entry.last_scan_attempt = datetime.now()
                binary_db_entry.save()
                cbint.globals.g_statistics.binaries_not_local += 1
                return

            self.binary_queue.put(binary_query[0], block=True, timeout=None)

    def update_global_statistics(self):
        cbint.globals.g_statistics.number_binaries_db = len(BinaryDetonationResult.select())
        cbint.globals.g_statistics.binaries_in_queue = self.binary_queue.qsize()

    def insert_binaries_from_db(self):
        """
        :return:
        """
        while True:
            self.update_global_statistics()
            try:
                #
                # Should we attempt to get binaries that are downloadable?
                # Configurable date for binaries?
                #
                for detonation in BinaryDetonationResult.select() \
                        .where(BinaryDetonationResult.binary_not_available.is_null()) \
                        .where(BinaryDetonationResult.last_scan_date.is_null() or \
                               BinaryDetonationResult.last_scan_date < datetime.today() - timedelta(days=180)) \
                        .order_by(BinaryDetonationResult.server_added_timestamp.desc()) \
                        .limit(100):
                    self.download_binary_insert_queue(detonation)
                    self.update_global_statistics()

                #
                # Next attempt to rescan binaries that needed to be downloaded by alliance
                #
                for detonation in self.get_possible_alliance_binary():
                    self.download_binary_insert_queue(detonation)
                    self.update_global_statistics()
            except Exception as e:
                logger.error(traceback.format_exc())
                report_error_statistics(str(e))

            time.sleep(.1)

    def generate_feed_from_db(self):
        """
        :return:
        """
        self.reports = []
        feed_results = BinaryDetonationResult.select().where(BinaryDetonationResult.score > 0)

        for result in feed_results:
            fields = {'iocs': {'md5': [result.md5]},
                      'score': result.score,
                      'timestamp': int(time.mktime(time.gmtime())),
                      'link': '',
                      'id': f'binary_{result.md5}',
                      'title': '',
                      'description': result.last_success_msg
                      }

            self.reports.append(CbReport(**fields))
            self.feed = CbFeed(self.feedinfo, self.reports)

        with open(os.path.join(cbint.globals.g_volume_directory, self.name, "feed", "feed.json"), 'w') as fp:
            fp.write(self.feed.dump())

    def report_successful_detonation(self, result: AnalysisResult):
        bdr = BinaryDetonationResult.get(BinaryDetonationResult.md5 == result.md5)
        bdr.score = result.score
        bdr.last_success_msg = result.short_result
        bdr.last_scan_date = bdr.last_scan_attempt = datetime.now()
        bdr.binary_not_available = False
        bdr.scan_count += 1
        bdr.save()

        cbint.globals.g_statistics.number_binaries_scanned += 1

        logger.info(f'{result.md5} scored at {result.score}')

        #
        # We want to update the feed if a new reports comes in with score > 0
        #
        if result.score > 0:
            self.generate_feed_from_db()

    def report_failure_detonation(self, result: AnalysisResult):
        bdr = BinaryDetonationResult.get(BinaryDetonationResult.md5 == result.md5)
        bdr.score = result.score
        bdr.last_error_msg = result.last_error_msg
        bdr.last_error_date = datetime.now()
        bdr.stop_future_scans = True
        bdr.save()

        logger.info(f'{result.md5} failed detonation')
