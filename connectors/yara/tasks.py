from celery import Celery

app = Celery('yara', backend='redis://localhost', broker='redis://localhost')
app.conf.task_serializer = "pickle"
app.conf.result_serializer = "pickle"
app.conf.accept_content = {"pickle"}

import yara
import time
import logging
import os
import traceback
import datetime
from cbint.analysis import AnalysisResult

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)


@app.task
def analyze_binary(yara_rule_map, md5sum, binary_data):
    global yara_rules
    logger.debug("%s: in analyze_binary" % md5sum)

    try:

        yara_rules = yara.compile(filepaths=yara_rule_map)

        analysis_result = AnalysisResult(md5sum)
        analysis_result.last_scan_date = datetime.datetime.now()

        try:
            matches = "debug"
            #matches = yara_rules.match(data=binary_data, timeout=30)
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
                #analysis_result.short_result = "Matched yara rules: %s" % ', '.join([match.rule for match in matches])
                analysis_result.short_result = "Matched yara rules: debug"
                analysis_result.long_result = analysis_result.long_result
            else:
                analysis_result.score = 0
    except:
        logger.error(traceback.format_exc())
        return None

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
