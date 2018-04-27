import yara
import time
import logging
import os
import traceback
import datetime
from cbint.detonation import BinaryDetonation
from cbint.analysis import AnalysisResult

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

yara_rules = None


def analyze_binary(md5sum, binary_file_stream):
    logger.debug("%s: in analyze_binary" % md5sum)
    d = binary_file_stream.read()

    analysis_result = AnalysisResult(md5sum)
    analysis_result.last_scan_date = datetime.datetime.now()

    try:
        start_analyze_time = time.time()
        matches = yara_rules.match(data=d, timeout=60)
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


def main():
    global yara_rules

    #
    # Should we move all these strings into a config file?
    #
    bd = BinaryDetonation(name="yara")

    bd.set_feed_info(name="Yara",
                     summary="Scan binaries collected by Carbon Black with Yara.",
                     tech_data="There are no requirements to share any data with Carbon Black to use this feed.",
                     provider_url="http://plusvic.github.io/yara/",
                     icon_path="icon/yara-logo.png",
                     display_name="Yara")

    yara_rules = compile_rules(os.path.join(bd.get_volume_directory(), 'yara_rules'))
    analysis_result = None
    for binary in bd.binaries_to_scan():
        logger.info(f"scanning {binary.md5}...")
        try:
            analysis_result = analyze_binary(binary.md5, binary.file)
            bd.report_successful_detonation(analysis_result)
        except Exception as e:
            if analysis_result:
                bd.report_failure_detonation(analysis_result)
            logger.error(traceback.format_exc())

        time.sleep(1)


if __name__ == '__main__':
    main()
