from celery import Celery

app = Celery('yaraconnector', backend='redis://localhost', broker='redis://localhost')
app.conf.task_serializer = "pickle"
app.conf.result_serializer = "pickle"
app.conf.accept_content = {"pickle"}

import cbapi
import yara
import time
import logging
import os
import traceback
import datetime
from cbint.analysis import AnalysisResult
from cbapi.response.models import Binary
from cbapi.response.rest_api import CbResponseAPI
import pprint

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)


@app.task
def analyze_binary(yara_rule_map, md5sum, cb_config):
    logger.debug("{}: in analyze_binary".format(md5sum))
    analysis_results = []
    try:

        cb = CbResponseAPI(url=cb_config.get("carbonblack_server_url"),
                           token=cb_config.get("carbonblack_server_token"),
                           ssl_verify=cb_config.getboolean("carbonblack_server_sslverify"))

        binary_query = cb.select(Binary).where(f"md5:{md5sum}")

        if binary_query:
            try:
                binary_data = binary_query[0].file.read()
            except:
                analysis_result = AnalysisResult(md5sum)
                analysis_result.last_scan_date = datetime.datetime.now()
                analysis_result.binary_not_available = True
                return [analysis_result]

            yara_rules = yara.compile(filepaths=yara_rule_map)

            try:
                # matches = "debug"
                matches = yara_rules.match(data=binary_data, timeout=30)
                pprint.pprint(matches)
            except yara.TimeoutError:
                #
                # yara timed out
                #
                analysis_result = AnalysisResult(md5sum)
                analysis_result.last_scan_date = datetime.datetime.now()
                analysis_result.last_error_msg = "Analysis timed out after 60 seconds"
                analysis_result.stop_future_scans = True
                analysis_results.append(analysis_result)
            except yara.Error:
                #
                # Yara errored while trying to scan binary
                #
                analysis_result = AnalysisResult(md5sum)
                analysis_result.last_scan_date = datetime.datetime.now()
                analysis_result.last_error_msg = "Yara exception"
                analysis_results.append(analysis_result)
            except:
                analysis_result = AnalysisResult(md5sum)
                analysis_result.last_scan_date = datetime.datetime.now()
                analysis_result.last_error_msg = traceback.format_exc()
                analysis_results.append(analysis_result)
            else:
                if matches:
                    for match in matches:
                        analysis_result = AnalysisResult(md5sum)
                        analysis_result.last_scan_date = datetime.datetime.now()
                        analysis_result.score = match.meta.get('score', 100)
                        analysis_result.scanner = match.rule
                        analysis_results.append(analysis_result)
        else:
            analysis_result = AnalysisResult(md5sum)
            analysis_result.last_scan_date = datetime.datetime.now()
            analysis_result.binary_not_available = True
            return [analysis_result]
        return analysis_results
    except:
        error = traceback.format_exc()
        analysis_result = AnalysisResult(md5sum)
        analysis_result.last_scan_date = datetime.datetime.now()
        analysis_result.binary_not_available = True
        analysis_result.last_error_msg = error
        return [analysis_result]
