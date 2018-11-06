import logging
import threading
import time
import traceback
import os
import hashlib
import json
import threading

from celery import group
from tasks import analyze_binary
from cbint.analysis import AnalysisResult
import cbint.globals
import xmlrpc.server
from xmlrpc.server import SimpleXMLRPCServer
from xmlrpc.server import SimpleXMLRPCRequestHandler
from cbint.detonation import BinaryDetonation, BinaryDetonationResult
from peewee import fn

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

bd = None

MAX_SCANS = 4



# Restrict to a particular path.
class RequestHandler(SimpleXMLRPCRequestHandler):
    rpc_paths = ('/RPC2',)

class YaraObject(threading.Thread):
    def __init__(self, bd):
        super().__init__()
        self.bd = bd
        self.yara_rule_map = self.generate_rule_map(self.get_yara_rules_directory())

    def generate_rule_map(self, pathname):
        global yara_rule_map_hash

        rule_map = {}
        for fn in os.listdir(pathname):
            fullpath = os.path.join(pathname, fn)
            if not os.path.isfile(fullpath):
                continue

            last_dot = fn.rfind('.')
            if last_dot != -1:
                namespace = fn[:last_dot]
            else:
                namespace = fn
            rule_map[namespace] = fullpath

        return rule_map

    def queue_binaries(self):
        try:
            scan_group = list()
            for i in range(MAX_SCANS):
                binary = next(bd.binaries_to_scan())
                md5 = binary[2]
                scan_group.append(analyze_binary.s(self.yara_rule_map, md5, cbint.globals.g_config))
            job = group(scan_group)

            result = job.apply_async()

            while not result.ready():
                time.sleep(.1)

            if result.successful():
                for analysis_result in result.get():
                    if analysis_result:
                        if analysis_result.last_error_msg:
                            bd.report_failure_detonation(analysis_result)
                        elif analysis_result.binary_not_available:
                            bd.report_binary_unavailable(analysis_result)
                        else:
                            analysis_result.misc = self.yara_rule_map
                            bd.report_successful_detonation(analysis_result)
            else:
                logger.error(result.traceback())
        except:
            logger.error(traceback.format_exc())
            time.sleep(5)

    def get_yara_rules_directory(self):
        return os.path.join("/vol", "yaraconnector", "yara_rules")

    def get_yara_rules(self):
        return self.yara_rule_map

    def forceRescanAll(self):
        self.bd.force_rescan_all()
        return True

    def get_result_for(self,hash):
        if len(BinaryDetonationResult.select().where(BinaryDetonationResult.md5==hash) > 0):
            try:
                return json.dumps(str(BinaryDetonationResult.select().where(BinaryDetonationResult.md5 == hash).get().model_to_dict()))
            except BaseException as e:
                return {"error":str(e)}
        else:
            return {}

    def executeBinaryQuery(self,query):
        ret = []
        try:
            cursor = self.bd.db_object.execute_sql(query)
            for value in cursor:
                logger.info(str(value))
                if value is not None:
                    ret.append([str(x) for x in value])
                if value is None:
                    ret.append(["None"])
        except BaseException as bae:
            ret.append([str({"error":str(bae),"query":query})])
        return ret if len(ret) > 0 else ["Result set was empty"]

    def check_yara_rules(self,forcerescan=False):
        new_rule_map = self.generate_rule_map(self.get_yara_rules_directory())
        if self.yara_rule_map != new_rule_map:
            logger.info("Detected a change in yara_rules directory")
            if forcerescan:
                logger.info("Rescanning after change in yara_rules directory...")
                self.bd.force_rescan_all()
            self.yara_rule_map = new_rule_map
            logger.info(new_rule_map)

    def getStatistics(self):
        bins_in_queue = self.bd.get_binary_queue().qsize()
        entries_in_db =  BinaryDetonationResult().select(fn.COUNT(BinaryDetonationResult.md5))
        scanned_bins = BinaryDetonationResult().select(fn.COUNT(BinaryDetonationResult.md5)).where(BinaryDetonationResult.last_scan_date)
        return {"queue":bins_in_queue,"dbentries":str(json.dumps(entries_in_db.dicts().get())),"scanned":str(json.dumps(scanned_bins.dicts().get()))}

    def getDebugLogs(self):
        return ["file://vol/yaraconnector/yaraconnector.log"]

    def getFeed(self):
        return ['file://vol/feeds/yaraconnector/feed.json']

    def getBinaryQueue(self):
        return [str(s) for s in self.bd.get_binary_queue().queue]

    def getFeedDump(self):
        try:
            return self.bd.get_feed_dump()
        except BaseException as bae:
            return str(bae)

    def run(self):
        while (True):
            self.queue_binaries()
            #self.check_yara_rules()
            logger.info(self.bd.binary_queue.qsize())


def main():
    global bd

    bd = BinaryDetonation(name="yaraconnector")

    yara_object = YaraObject(bd)

    bd.set_feed_info(name="Yara",
                     summary="Scan binaries collected by Carbon Black with Yara.",
                     tech_data="There are no requirements to share any data with Carbon Black to use this feed.",
                     provider_url="http://plusvic.github.io/yara/",
                     icon_path="yara-logo.png",
                     display_name="Yara")

    yara_object.start()

    # Create server
    try:
        with SimpleXMLRPCServer(('localhost', 9002),
                            requestHandler=RequestHandler,allow_none=True) as server:
            server.register_introspection_functions()


            server.register_instance(yara_object)

            # Run the server's main loop
            server.serve_forever()

    finally:
        bd.close()



if __name__ == '__main__':
    main()
