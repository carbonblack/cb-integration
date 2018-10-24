import logging
import threading
import time
import traceback
import os
import hashlib
import threading

from celery import group
from tasks import analyze_binary
from cbint.analysis import AnalysisResult

from cbint.detonation import BinaryDetonation

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

bd = None

MAX_SCANS = 4


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
                scan_group.append(analyze_binary.s(self.yara_rule_map, binary.md5, binary.file.read()))
            job = group(scan_group)

            result = job.apply_async()

            while not result.ready():
                time.sleep(.1)

            if result.successful():
                for analysis_result in result.get():
                    if analysis_result:
                        if analysis_result.last_error_msg:
                            bd.report_failure_detonation(analysis_result)
                        else:
                            analysis_result.misc = self.yara_rule_map
                            bd.report_successful_detonation(analysis_result)
            else:
                logger.error(result.traceback())
        except:
            logger.error(traceback.format_exc())
            time.sleep(5)

    def get_yara_rules_directory(self):
        return os.path.join(bd.get_volume_directory(), "yara", "yara_rules")

    def check_yara_rules(self):
        new_rule_map = self.generate_rule_map(self.get_yara_rules_directory())
        if self.yara_rule_map != new_rule_map:
            logger.info("Detected a change in yara_rules directory")
            self.yara_rule_map = new_rule_map
            logger.info(new_rule_map)

    def run(self):
        while (True):
            self.queue_binaries()
            #self.check_yara_rules()
            logger.info(self.bd.binary_queue.qsize())


def main():
    global bd

    bd = BinaryDetonation(name="yara")

    yara_object = YaraObject(bd)

    bd.set_feed_info(name="Yara",
                     summary="Scan binaries collected by Carbon Black with Yara.",
                     tech_data="There are no requirements to share any data with Carbon Black to use this feed.",
                     provider_url="http://plusvic.github.io/yara/",
                     icon_path="icon/yara-logo.png",
                     display_name="Yara")

    yara_object.start()

    while True:
        time.sleep(60)


if __name__ == '__main__':
    main()
