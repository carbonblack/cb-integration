from celery import Celery
import base64

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

def compile_rules(pathname):
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
    return yara.compile(filepaths=rule_map)

yara_rules = compile_rules(os.path.join(os.getcwd(), '../../vol/yara/yara_rules'))

@app.task
def analyze_binary(md5sum, binary_data):
    logger.debug("%s: in analyze_binary" % md5sum)

    analysis_result = AnalysisResult(md5sum)
    analysis_result.last_scan_date = datetime.datetime.now()

    try:
        start_analyze_time = time.time()
        matches = yara_rules.match(data=binary_data, timeout=60)
        end_analyze_time = time.time()
        logger.debug("%s: Took %0.3f seconds to analyze the file" % (md5sum, end_analyze_time - start_analyze_time))
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
            analysis_result.short_result = "Matched yara rules: %s" % ', '.join([match.rule for match in matches])
            analysis_result.long_result = analysis_result.long_result
        else:
            analysis_result.score = 0

    return analysis_result


def getHighScore(matches):
    score = 0
    for match in matches:
        if match.meta.get('score', 0) > score:
            score = match.meta.get('score')
    if score == 0:
        return 100
    else:
        return score
