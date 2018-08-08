import logging
import threading
import time
import traceback

from celery import group
from tasks import analyze_binary

from cbint.detonation import BinaryDetonation

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

bd = None

MAX_SCANS = 4


def queue_binaries():
    while True:
        try:
            scan_group = list()
            for i in range(MAX_SCANS):
                binary = next(bd.binaries_to_scan())
                scan_group.append(analyze_binary.s(binary.md5, binary.file.read()))
            job = group(scan_group)

            result = job.apply_async()

            while not result.ready():
                time.sleep(.1)

            if result.successful():
                for analysis_result in result.get():
                    if analysis_result.last_error_msg:
                        bd.report_failure_detonation(analysis_result)
                    else:
                        bd.report_successful_detonation(analysis_result)
            else:
                logger.error(result.traceback())
        except:
            logger.error(traceback.format_exc())
            time.sleep(3)
            continue


def main():
    global bd
    bd = BinaryDetonation(name="bluecoat")

    bd.set_feed_info(name="bluecoat",
                     summary="Scan binaries collected by Carbon Black with bluecoat.",
                     tech_data="There are no requirements to share any data with Carbon Black to use this feed.",
                     provider_url="http://plusvic.github.io/bluecoat/",
                     icon_path="icon/bluecoat-logo.png",
                     display_name="bluecoat")

    queue_binaries_to_scan_thread = threading.Thread(target=queue_binaries)
    queue_binaries_to_scan_thread.daemon = True
    queue_binaries_to_scan_thread.start()

    while True:
        time.sleep(1)


if __name__ == '__main__':
    main()
