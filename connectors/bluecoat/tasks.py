from celery import Celery

app = Celery('yara', backend='redis://localhost', broker='redis://localhost')
app.conf.task_serializer = "pickle"
app.conf.result_serializer = "pickle"
app.conf.accept_content = {"pickle"}

import logging
import os
import traceback
from cbint.analysis import AnalysisResult

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

bluecoat_config = SafeConfigParser(os.path.join(os.getcwd(), "../../vol/bluecoat/bluecoat.conf"))

bluecoat_min_score_threshold = bluecoat_config.get("bluecoat_min_score_threshold", 50)
headers = {'X-API-TOKEN': bluecoat_config.get("bluecoat_api_key", "")}

sample_upload_url = "{0}rapi/samples/basic".format(bluecoat_config.bluecoat_url)
create_task_url = "{0}rapi/tasks".format(bluecoat_config.bluecoat_url)

check_url_format_str = "{0}rapi/samples?md5=".format(bluecoat_config.bluecoat_url)
get_tasks_url_format_str = "{0}rapi/samples/%%d/tasks".format(bluecoat_config.bluecoat_url)

session = get_tlsv1_2_session()


def check_result_for(self, md5sum, sample_id=None):
    try:
        if not sample_id:
            #
            # if no sample_id then try md5sum
            #
            url = "{0}rapi/samples?md5={1}".format(bluecoat_config.get('bluecoat_url'), md5sum)

            #
            # Send the get request
            #
            resp = self.session.get(url, headers=self.headers, verify=False)

            #
            # Parse the results
            #
            sample_results = resp.json()
            result_count = sample_results.get('results_count', 0)
            if result_count == 0:
                #
                # if there are no results return None
                #
                return None

            result = sample_results.get('results', [{}])[0]
            sample_id = result.get('samples_sample_id', -1)

        url = self.get_tasks_url_format_str % sample_id
        resp = self.session.get(url, headers=self.headers, verify=False)

        logger.warn("%s | %d" % (url, resp.status_code))

        tasks_results = resp.json()
        #
        # Inside of tasks_results if there are none then it will be an empty list
        #
        task_result = tasks_results.get('results', [{}])
        if len(task_result) == 0:
            return None

        #
        # Here task_result is a [{}]
        #
        task_result = task_result[0]

        task_id = task_result.get('tasks_task_id', -1)
        if not task_id:  #
            #
            # No task associated with this sample id
            #
            return None

        #
        # Get the current task state
        #
        task_status = task_result.get('task_state_state', 'UNKNOWN')
        if task_status == 'CORE_COMPLETE':

            #
            # Pull the score from json
            #
            score = task_result['tasks_global_risk_score']

            logger.info("Binary %s score %d" % (md5sum, score))

            #
            # Normalize score by just multiplying
            #
            score *= 10

            #
            # check against min_score_threshold.  If score is less than or equal to threshold then mark score as 0
            # We do this because bluecoat will give results of 10-40 for binaries that are benign.
            #
            if score <= self.bluecoat_min_score_threshold:
                score = 0
                malware_result = "Benign"
            else:
                malware_result = "Potential Malware"

            #
            # generate the task link to send back with the Analysis Result
            #
            task_link = "%sanalysis_center/view_task/%d" % (self.bluecoat_url, task_id)

            return AnalysisResult(message=malware_result, extended_message="",
                                  link=task_link,
                                  score=score)
        else:
            #
            # Since this is called from a quick scan thread just return None
            # if the bluecoat provider returns anything besides CORE_COMPLETE
            #
            return None

    except Exception as e:
        logger.error("check_result_for: an exception occurred while querying bluecoat for %s: %s" % (md5sum, e))
        logger.error(traceback.format_exc())
        raise AnalysisTemporaryError(message=e.message, retry_in=120)


def analyze_binary(self, md5sum, binary_file_stream):
    try:
        description = 'Uploaded from Carbon Black'
        label = 'cb-%s' % md5sum

        sample_file = {'file': binary_file_stream}
        form_data = {'owner': self.bluecoat_owner, 'description': description, 'label': label}

        #
        # Upload the binary
        #
        resp = self.session.post(self.sample_upload_url,
                                 files=sample_file,
                                 data=form_data,
                                 headers=self.headers,
                                 verify=False)
        logger.info("%s | %d" % (self.sample_upload_url, resp.status_code))

        if resp.status_code != 200:
            raise AnalysisTemporaryError(message=resp.content, retry_in=120)

        #
        # Check the response of the upload
        #
        sample_upload_data = resp.json()
        sample_result = sample_upload_data.get('results', [{}])[0]

        #
        # Now create the task to analyze the binary
        #
        sample_id = sample_result.get('samples_sample_id')
        task_data = {"sample_id": sample_id, "env": "ivm"}

        #
        # Send the Http Post to create the task
        #
        resp = self.session.post(self.create_task_url, data=task_data, headers=self.headers, verify=False)
        logger.info("%s | %d" % (self.create_task_url, resp.status_code))

        if resp.status_code != 200:
            raise AnalysisTemporaryError(message=resp.content, retry_in=120)

        #
        # Try to get the results if we can
        #
        retries = 20
        while retries:
            sleep(10)
            result = self.check_result_for(md5sum, sample_id=sample_id)
            if result:
                return result
            retries -= 1

        raise AnalysisTemporaryError(message="Maximum retries (20) exceeded submitting to Bluecoat", retry_in=120)

    except Exception as e:
        logger.error("analyze_binary: an exception occurred while submitting to bluecoat for %s: %s" % (md5sum, e))
        logger.error(traceback.format_exc())
        raise AnalysisTemporaryError(traceback.format_exc(), retry_in=120)
