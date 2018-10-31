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

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)


@app.task
def analyze_binary(yara_rule_map, md5sum, cb_config):
    logger.debug("{}: in analyze_binary".format(md5sum))

    try:
        analysis_result = AnalysisResult(md5sum)
        analysis_result.last_scan_date = datetime.datetime.now()

        cb = CbResponseAPI(url=cb_config.get("carbonblack_server_url"),
                           token=cb_config.get("carbonblack_server_token"),
                           ssl_verify=cb_config.getboolean("carbonblack_server_sslverify"))

        binary_query = cb.select(Binary).where(f"md5:{md5sum}")

        if binary_query:
            try:
                binary_data = binary_query[0].file.read()
            except:
                analysis_result.binary_not_available = True
                return analysis_result

            yara_rules = yara.compile(filepaths=yara_rule_map)

            try:
                #matches = "debug"
                matches = yara_rules.match(data=binary_data, timeout=30)
            except yara.TimeoutError:
                #
                # yara timed out
                #
                analysis_result.last_error_msg = "Analysis timed out after 60 seconds"
                analysis_result.stop_future_scans = True
            except yara.Error:
                #
                # Yara errored while trying to scan binary
                #
                analysis_result.last_error_msg = "Yara exception"
            except:
                analysis_result.last_error_msg = traceback.format_exc()
            else:
                if matches:
                    score = getHighScore(matches)
                    analysis_result.score = score
                    # analysis_result.short_result = "Matched yara rules: %s" % ', '.join([match.rule for match in matches])
                    analysis_result.short_result = "Matched yara rules: debug"
                    analysis_result.long_result = analysis_result.long_result
                else:
                    analysis_result.score = 0
        else:
            analysis_result.binary_not_available = True
        return analysis_result
    except:
        error = traceback.format_exc()
        analysis_result.last_error_msg = error
        return analysis_result

def getHighScore(matches):
    #######
    if matches == "debug":
        return 0
    #######
    score = 0
    for match in matches:
        if match.meta.get('score', 0) > score:
            score = match.meta.get('score')
    if score == 0:
        return 100
    else:
        return score
