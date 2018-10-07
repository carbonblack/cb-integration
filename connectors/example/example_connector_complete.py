import datetime
import logging
import time
import traceback
import requests

from cbint.analysis import AnalysisResult
from cbint.detonation import BinaryDetonation

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

bd = BinaryDetonation(name="example")


def analyze_binary(md5sum, binary_file_stream):
    """
    :param md5sum: md5 of the binary
    :param binary_file_stream: stream object of the executable
    :return: AnalysisResult
    """

    #
    # Create an AnalysisResult object to store the results
    #
    analysis_result = AnalysisResult(md5sum)
    #
    # Set the last scan date.  This helps the binary algorithm with regard to rescans.
    #
    analysis_result.last_scan_date = datetime.datetime.now()

    try:
        #
        # Set the default score of the binary
        #
        score = 1

        #
        # Read the binary
        #
        binary_data = binary_file_stream.read()

        #
        # do your work here
        #
        awful_url = bd.get_config().get('awful_analyzer_url', '')

        res = requests.post(url='{0}/upload_sample'.format(awful_url),
                            files=dict(sample=str(binary_data)))

        job_id = None
        if 'job_id' in res.json():
            job_id = res.json().get('job_id', '')
            logger.info('got job_id:{}'.format(job_id))

        if not job_id:
            #
            # Error
            #
            analysis_result.last_error_msg = ''
            if 'error' in res.json():
                analysis_result.last_error_msg = res.json().get('error', '')
            return analysis_result

        for i in range(300):

            res = requests.get(url='{0}/get_result/{1}'.format(awful_url, job_id))
            # logger.info(res.json())

            if 'result' in res.json():
                score = int(res.json().get('result'))
                logger.info('got score:{}'.format(score))
                break
            elif 'error' in res.json():
                if res.json().get('error', '') == "pending":
                    pass
                else:
                    analysis_result.last_error_msg = res.json().get('error', '')

            time.sleep(3)

    except Exception as e:
        #
        # There was a generic error.
        # Save off the exception string in the last_error_msg and stop future scans of this binary.
        #
        analysis_result.last_error_msg = str(e)
        analysis_result.stop_future_scans = True
    else:
        #
        # Successful scan.  Save off score and any context information
        #
        analysis_result.score = score
        analysis_result.short_result = ""
        analysis_result.long_result = ""

    return analysis_result


def main():
    """
    Entry point to this connector.
    :return: None
    """

    bd.set_feed_info(name="example",
                     summary="Summary of function of this connector",
                     tech_data="There are no requirements to share any data with Carbon Black to use this feed.",
                     provider_url="provider_url",
                     icon_path="icon/example-logo.png",
                     display_name="example")

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
        time.sleep(3)


if __name__ == '__main__':
    main()
