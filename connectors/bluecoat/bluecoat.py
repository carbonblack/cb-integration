from cbint.utils.detonation import DetonationDaemon, ConfigurationError
from cbint.utils.detonation.binary_analysis import (BinaryAnalysisProvider, AnalysisPermanentError,
                                                    AnalysisTemporaryError, AnalysisResult)
import cbint.utils.feed
import logging
import requests
import traceback
from time import sleep
from cbint.utils.tls import get_tlsv1_2_session

logging.getLogger("requests").setLevel(logging.WARNING)

log = logging.getLogger(__name__)


class BluecoatProvider(BinaryAnalysisProvider):
    def __init__(self, name, bluecoat_url, bluecoat_api_key, bluecoat_owner, bluecoat_min_score_threshold):
        super(BluecoatProvider, self).__init__(name)

        # TODO -- pass in whether or not to verify ???

        self.bluecoat_url = bluecoat_url
        if not self.bluecoat_url.endswith('/'):
            self.bluecoat_url += "/"

        self.bluecoat_api_key = bluecoat_api_key
        self.bluecoat_owner = bluecoat_owner
        self.bluecoat_min_score_threshold = bluecoat_min_score_threshold
        self.headers = {'X-API-TOKEN': self.bluecoat_api_key}

        self.sample_upload_url = "%srapi/samples/basic" % self.bluecoat_url
        self.create_task_url = "%srapi/tasks" % self.bluecoat_url

        self.check_url_format_str = "%srapi/samples?md5=%%s" % (self.bluecoat_url)
        self.get_tasks_url_format_str = "%srapi/samples/%%d/tasks" % self.bluecoat_url

        self.session = get_tlsv1_2_session()

    def scale_score(self, value, base_min, base_max, limit_min, limit_max):
        return ((limit_max - limit_min) * (value - base_min) / (base_max - base_min)) + limit_min

    def check_result_for(self, md5sum, sample_id=None):
        try:
            if not sample_id:
                #
                # if no sample_id then try md5sum
                #
                url = self.check_url_format_str % md5sum

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

            log.warn("%s | %d" % (url, resp.status_code))

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

                log.info("Binary %s score %d" % (md5sum, score))

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
            log.error("check_result_for: an exception occurred while querying bluecoat for %s: %s" % (md5sum, e))
            log.error(traceback.format_exc())
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
            log.info("%s | %d" % (self.sample_upload_url, resp.status_code))

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
            log.info("%s | %d" % (self.create_task_url, resp.status_code))

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
            log.error("analyze_binary: an exception occurred while submitting to bluecoat for %s: %s" % (md5sum, e))
            log.error(traceback.format_exc())
            raise AnalysisTemporaryError(traceback.format_exc(), retry_in=120)


class BluecoatConnector(DetonationDaemon):

    @property
    def integration_name(self):
        return 'Cb BlueCoat Connector 1.2.9'

    @property
    def filter_spec(self):
        filters = []
        max_module_len = 10 * 1024 * 1024
        filters.append('os_type:windows orig_mod_len:[1 TO %d]' % max_module_len)
        additional_filter_requirements = self.get_config_string("binary_filter_query", None)
        if additional_filter_requirements:
            filters.append(additional_filter_requirements)
        return ' '.join(filters)

    @property
    def num_quick_scan_threads(self):
        return 0

    @property
    def num_deep_scan_threads(self):
        bluecoat_num_threads = self.get_config_integer("bluecoat_num_threads", 4)
        log.info("Number of deep scan threads: {0}".format(bluecoat_num_threads))
        return bluecoat_num_threads

    def get_provider(self):
        bluecoat_provider = BluecoatProvider(self.name,
                                             self.bluecoat_url,
                                             self.bluecoat_api_key,
                                             self.bluecoat_owner,
                                             self.bluecoat_min_score_threshold)
        return bluecoat_provider

    def get_metadata(self):
        return cbint.utils.feed.generate_feed(self.name, summary="Bluecoat Malware Analysis Appliance Detonation",
                                              tech_data="There are no requirements to share any data with Carbon Black to use this feed.",
                                              provider_url="http://www.bluecoat.com",
                                              icon_path='/usr/share/cb/integrations/bluecoat/bluecoat-logo.png',
                                              display_name="Bluecoat", category="Connectors")

    def validate_config(self):
        super(BluecoatConnector, self).validate_config()
        self.check_required_options(["bluecoat_url", "bluecoat_api_key"])
        self.bluecoat_url = self.get_config_string("bluecoat_url", None)
        self.bluecoat_api_key = self.get_config_string("bluecoat_api_key", None)
        self.bluecoat_owner = self.get_config_string("bluecoat_owner", "admin")
        self.bluecoat_min_score_threshold = int(self.get_config_string("min_score_threshold", "50"))
        return True


if __name__ == '__main__':
    import os

    my_path = os.path.dirname(os.path.abspath(__file__))
    temp_directory = "/tmp/bluecoat"

    config_path = os.path.join(my_path, "testing.conf")
    daemon = BluecoatConnector('bluecoattest', configfile=config_path, work_directory=temp_directory,
                               logfile=os.path.join(temp_directory, 'test.log'), debug=True)
    daemon.start()