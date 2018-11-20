import base64
import logging
import os
import queue
import threading
import time
import traceback
from datetime import datetime, timedelta
import json
from peewee import DateTimeField

from cbapi.errors import *
from cbapi.response.models import Binary
from cbapi.response.rest_api import CbResponseAPI

import cbint.globals
from cbint.analysis import AnalysisResult
from cbint.binary_collector import BinaryCollector
from cbint.binary_database import BinaryDetonationResult
from cbint.binary_database import db
from cbint.cbfeeds import CbReport, CbFeed
from cbint.integration import Integration
from cbint.utils.helpers import report_error_statistics
from cbint.message_bus import CBAsyncConsumer
from cbint.flask_feed import app
from peewee import fn,SQL

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

BINARY_QUEUE_MAX_SIZE = 2000


class BinaryDetonation(Integration):
    def __init__(self, name=""):
        super().__init__(name=name)
        self.binary_queue = queue.PriorityQueue(maxsize=BINARY_QUEUE_MAX_SIZE)
        self.feed = None

        #
        # Connect to the sqlite db and make sure the tables are created
        #

        logger.debug("Attempting to connect to sqlite database...")
        try:
            db.init(os.path.join("/vol", self.name, "db", "binary.db"))
            # db.init(os.path.join(cbint.globals.g_volume_directory, "binary.db"))
            logger.debug("Binary Db Path: {0}".format(
                os.path.join("/vol", self.name, "db", "binary.db")))
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
        bc = BinaryCollector(query=cbint.globals.g_config.get("binary_filter_query"), queue=self.binary_queue)
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

        amqp_url = cbint.globals.g_config.get("amqp_url")

        def submit_binary_to_db_and_queue(message):
            logger.debug("Submitting binary to db and queue")
            with db.transaction() as txn:
                try:
                    det = BinaryDetonationResult()
                    msg = json.loads(message)
                    det.md5 = msg.get("md5")
                    det.from_rabbitmq = True
                    #det.server_added_timestamp = datetime.fromtimestamp(
                    #    msg.get("event_timestamp")).isoformat()  # datetime.fromtimestamp(msg.get("event_timestamp"))
                    #
                    # Save into database
                    #
                    det.save()
                    self.binary_insert_queue(det.md5, 1)
                except Exception as e:
                    logger.debug("Exception in async consumer....")
                    logger.debug(e)

        self.cbasyncconsumer = CBAsyncConsumer(amqp_url=amqp_url,
                                               exchange='api.events',
                                               queue='binarystore',
                                               routing_key='binarystore.file.added',
                                               exchange_type='topic',
                                               exchange_durable=True,
                                               arguments={'x-max-length': 10000},
                                               worker=submit_binary_to_db_and_queue
                                               )

        logger.debug("Starting async consumer")
        self.asyncconsumer_thread = threading.Thread(target=self.cbasyncconsumer.run)
        self.asyncconsumer_thread.daemon = True
        self.asyncconsumer_thread.start()
        logger.debug("Async consumer running")
        cbint.globals.g_integration = self
        logger.debug("init complete")

    def get_binary_queue(self):
        return self.binary_queue

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
            md5 = self.binary_queue.get(block=True, timeout=None)
            self.binary_queue.task_done()
            if not md5:
                continue
            yield md5

    def binary_insert_queue(self, md5, priority=2):
        self.binary_queue.put((priority, time.time(), md5), block=True, timeout=None)

    def update_global_statistics(self):
        cbint.globals.g_statistics.binaries_in_queue = self.binary_queue.qsize()

    def insert_binaries_from_db(self):
        """
        :return:
        """
        just_inserted_server_added_timestamp = None
        try:
            while True:
                self.update_global_statistics()
                try:

                    # Get the first 500 binaries after the newest one we just inserted
                    if just_inserted_server_added_timestamp is None:
                        query = BinaryDetonationResult.select(BinaryDetonationResult.md5,BinaryDetonationResult.server_added_timestamp) \
                            .where((BinaryDetonationResult.binary_not_available.is_null()) | \
                                   (BinaryDetonationResult.last_scan_date.is_null()) | \
                                   (BinaryDetonationResult.force_rescan == True)) \
                            .order_by(BinaryDetonationResult.server_added_timestamp.asc()).limit(500)
                    else:
                        query = BinaryDetonationResult.select(BinaryDetonationResult.md5,BinaryDetonationResult.server_added_timestamp) \
                            .where(((BinaryDetonationResult.binary_not_available.is_null()) | \
                                   (BinaryDetonationResult.last_scan_date.is_null()) | \
                                   (BinaryDetonationResult.force_rescan == True)) & \
                                   (BinaryDetonationResult.server_added_timestamp >= just_inserted_server_added_timestamp)) \
                            .order_by(BinaryDetonationResult.server_added_timestamp.asc()).limit(500)

                    cursor = db.execute(query)

                    added_timestamp=None
                    for item in cursor:
                        md5 = item[0]
                        added_timestamp = item[1]
                        self.binary_insert_queue(md5)
                        self.update_global_statistics()
                    just_inserted_server_added_timestamp = added_timestamp

                    #
                    # Next attempt to rescan binaries that needed to be downloaded by alliance
                    #
                    for detonation in BinaryDetonationResult.select() \
                            .where((BinaryDetonationResult.binary_not_available == True) & \
                                   (BinaryDetonationResult.last_scan_attempt < datetime.today() - timedelta(days=1))) \
                            .order_by(BinaryDetonationResult.last_scan_attempt.asc()):
                        self.binary_insert_queue(detonation.md5)
                        self.update_global_statistics()
                except Exception as e:
                    logger.error(traceback.format_exc())
                    report_error_statistics(str(e))

                time.sleep(.1)
        except:
            logger.error(traceback.format_exc())
            time.sleep(30)

    def force_rescan_all(self):
        logger.info("Forcing rescan on all present binaries")
        query = BinaryDetonationResult.update(force_rescan=True).where(BinaryDetonationResult.scan_count > 0)
        query.execute()

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

        with open(os.path.join("/vol", self.name, "feed", "feed.json"), 'w') as fp:
            fp.write(self.feed.dump())

    def get_feed_dump(self, generate_new_feed=True):
        if self.feed is not None:
            return self.feed.dumpjson()
        else:
            if generate_new_feed:
                self.generate_feed_from_db()
                if self.feed is not None:
                    return self.feed.dumpjson()
                return self.feedinfo
            else:
                return {}

    def executeBinaryQuery(self,query):
        ret = []
        try:
            cursor = self.db_object.execute_sql(query)
            for value in cursor:
                logger.info(str(value))
                if value is not None:
                    ret.append([str(x) for x in value])
                if value is None:
                    ret.append(["None"])
        except BaseException as bae:
            ret.append([str({"error":str(bae),"query":query})])
        return ret if len(ret) > 0 else ["Result set was empty"]

    def get_result_for(self, hash):
        if len(BinaryDetonationResult.select().where(BinaryDetonationResult.md5 == hash) > 0):
            try:
                return json.dumps(str(
                    BinaryDetonationResult.select().where(BinaryDetonationResult.md5 == hash).get().model_to_dict()))
            except BaseException as e:
                return {"error": str(e)}
        else:
            return {}

    def getStatistics(self):
        bins_in_queue = self.get_binary_queue().qsize()
        entries_in_db =  len(BinaryDetonationResult().select())
        scanned_bins = BinaryDetonationResult().select(fn.COUNT(BinaryDetonationResult.md5)).where(BinaryDetonationResult.last_scan_date)
        rates = BinaryDetonationResult().select(fn.COUNT(BinaryDetonationResult.md5).alias('rate')).where(BinaryDetonationResult.last_scan_date).group_by(fn.date_trunc('minute',BinaryDetonationResult.last_scan_date)).order_by(SQL('rate')).dicts()
        therate = 0.0
        sum_rates = 0.0
        count = 0
        minrate = -1
        maxrate = 0
        for rate in rates:
            therate = rate['rate']
            sum_rates += therate
            minrate = therate if therate < minrate else (minrate if minrate is not -1 else therate)
            maxrate = therate if therate >= maxrate else therate
            count += 1
        avgrate = sum_rates / count if count > 0 else 1
        return {"dbentries":str(entries_in_db),"Maximum 1 minute scanning rate":str(maxrate),"Average 1 minute scanning rate":str(avgrate),"scanned":str(json.dumps(scanned_bins.dicts().get()))}

    def report_successful_detonation(self, result: AnalysisResult):
        bdr = BinaryDetonationResult.get(BinaryDetonationResult.md5 == result.md5)
        bdr.score = result.score
        bdr.last_success_msg = result.short_result
        bdr.last_scan_date = bdr.last_scan_attempt = datetime.now()
        bdr.binary_not_available = False
        bdr.scan_count += 1
        if bdr.force_rescan == True:
            logger.info("rescan was True now set to False")
            bdr.force_rescan = False
        bdr.save()

        cbint.globals.g_statistics.number_binaries_scanned += 1

        # logger.info(f'{result.md5} scored at {result.score}')

        #
        # We want to update the feed if a new reports comes in with score > 0
        #
        if result.score > 0:
            self.generate_feed_from_db()

    def report_failure_detonation(self, result: AnalysisResult):
        logger.info(result)
        bdr = BinaryDetonationResult.get(BinaryDetonationResult.md5 == result.md5)
        bdr.score = result.score
        bdr.last_error_msg = result.last_error_msg
        bdr.last_error_date = datetime.now()
        bdr.stop_future_scans = True
        if bdr.force_rescan == True:
            logger.info("rescan was True now set to False")
            bdr.force_rescan = False
        bdr.save()

        logger.info(f'{result.md5} failed detonation')

    def report_binary_unavailable(self, result: AnalysisResult):
        bdr = BinaryDetonationResult.get(BinaryDetonationResult.md5 == result.md5)
        bdr.binary_not_available = True
        bdr.num_attempts += 1
        bdr.last_scan_attempt = datetime.now()
        bdr.save()
        cbint.globals.g_statistics.binaries_not_local += 1

    # cleanup
    def close(self):
        self.db_object.close()
