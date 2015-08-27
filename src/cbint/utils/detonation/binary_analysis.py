import threading
import datetime
import traceback
from cbapi.util.messaging_helpers import QueuedCbSubscriber
from time import sleep
import json
from zipfile import ZipFile
from cStringIO import StringIO
import time
import logging


log = logging.getLogger(__name__)

class CbAPIProducerThread(threading.Thread):
    def __init__(self, work_queue, cb, name, max_rows=None, sleep_between=60, rate_limiter=0.1, stop_when_done=False,
                 filter_spec=''):
        threading.Thread.__init__(self)
        self.queue = work_queue
        self.done = False
        self.cb = cb
        self.feed_name = name
        self.sleep_between = sleep_between
        self.max_rows = max_rows
        self.rate_limiter = rate_limiter
        self.stop_when_done = stop_when_done
        self.filter_spec = filter_spec

    def stop(self):
        self.done = True

    def run(self):
        while not self.done:
            # TODO: retry logic - make sure we don't bomb out if this fails
            query_string = '-alliance_score_%s %s' % (self.feed_name, self.filter_spec)
            log.debug("Querying cb for binaries matching '%s'" % query_string)
            try:
                for i,binary in enumerate(self.cb.binary_search_iter(query_string, sort="server_added_timestamp desc")):
                    if self.done:
                        return

                    # TODO: keep track of server_added_timestamp if we have it, and use that to filter next time
                    if not self.queue.append(binary['md5']):
                        pass
                        # print 'md5 %s already tracked' % (binary['md5'],)

                    sleep(self.rate_limiter)        # no need to flood the Cb server or ourselves with binaries

                    if self.max_rows and i > self.max_rows:
                        break
            except Exception as e:
                log.error("Error during binary enumeration: %s. Sleeping for %f seconds and retrying."
                          % (str(e), self.sleep_between))

            if self.stop_when_done:
                self.done = True
            else:
                sleep(self.sleep_between)


class CbStreamingProducerThread(QueuedCbSubscriber):
    def __init__(self, queue, cb_server_address, rmq_username, rmq_password):
        super(CbStreamingProducerThread, self).__init__(cb_server_address, rmq_username, rmq_password,
                                                        "binarystore.file.added")
        self.queue = queue
        print 'streaming producer inited'

    def consume_message(self, channel, method_frame, header_frame, body):
        if header_frame.content_type != 'application/json':
            return

        msg = json.loads(body)
        print 'got streaming msg: %s' % msg
        if not self.queue.append(msg['md5'], file_available=True):
            pass
            # print 'md5 %s already tracked' % (msg['md5'],)


class AnalysisPermanentError(Exception):
    def __init__(self, message="", extended_message="", analysis_version=1):
        super(AnalysisPermanentError, self).__init__(message)
        self.extended_message = extended_message
        self.analysis_version = analysis_version


class AnalysisTemporaryError(Exception):
    def __init__(self, message="", extended_message="", retry_in=60, analysis_version=1):
        super(AnalysisTemporaryError, self).__init__(message)
        try:
            self.retry_in = int(retry_in)
        except ValueError:
            log.warn("programming error: retry_in is not an integer (was %s; message=%s)" % (retry_in, message))
            self.retry_in = 60

        self.extended_message = extended_message
        self.analysis_version = analysis_version


class AnalysisResult(object):
    def __init__(self, message="", extended_message="", analysis_version=1, score=0):
        self.score = score
        self.message = message
        self.extended_message = extended_message
        self.analysis_version = analysis_version


class BinaryAnalysisProvider(object):
    def __init__(self, name):
        self.name = name

    def check_result_for(self, md5sum):
        # can return an AnalysisResult() or None (no results for that md5sum)
        return None

    def analyze_binary(self, md5sum, binary_file_stream):
        # can return either:
        # AnalysisResult()
        # or throw an exception:
        # throw AnalysisPermanentError()
        # throw AnalysisTemporaryError()
        pass


class BinaryConsumerThread(threading.Thread):
    def __init__(self, work_queue, cb, provider, dirty_event):
        threading.Thread.__init__(self)
        self.queue = work_queue
        self.done = False
        self.provider = provider
        self.cb = cb
        self.dirty_event = dirty_event

    def stop(self):
        self.done = True

    def save_successful_analysis(self, md5sum, analysis_result):
        self.queue.mark_as_analyzed(md5sum, True, analysis_result.analysis_version, analysis_result.message,
                                    analysis_result.extended_message, score=analysis_result.score)
        self.dirty_event.set()

    def save_unsuccessful_analysis(self, md5sum, e):
        if type(e) == AnalysisTemporaryError:
            retry_in_seconds = int(e.retry_in)
            self.queue.mark_as_analyzed(md5sum, False, e.analysis_version, e.message, e.extended_message,
                                        retry_at=datetime.datetime.now()+datetime.timedelta(seconds=retry_in_seconds))
        elif type(e) == AnalysisPermanentError:
            self.queue.mark_as_analyzed(md5sum, False, e.analysis_version, e.message, e.extended_message)
        else:
            self.queue.mark_as_analyzed(md5sum, False, 0, "%s: %s" % (e.__class__.__name__, e.message),
                                        "%s" % traceback.format_exc())

    def save_empty_quick_scan(self, md5sum):
        self.queue.mark_quick_scan_complete(md5sum)


class QuickScanThread(BinaryConsumerThread):
    def quick_scan(self, md5sum):
        try:
            res = self.provider.check_result_for(md5sum)
            if type(res) == AnalysisResult:
                self.save_successful_analysis(md5sum, res)
            else:
                self.save_empty_quick_scan(md5sum)
        except AnalysisTemporaryError as e:
            self.save_unsuccessful_analysis(md5sum, e)
        except AnalysisPermanentError as e:
            self.save_unsuccessful_analysis(md5sum, e)
        except Exception as e:
            self.save_unsuccessful_analysis(md5sum, AnalysisTemporaryError(message="Exception in check_result_for",
                                                                           extended_message=traceback.format_exc()))

    def run(self):
        while not self.done:
            md5sum = self.queue.get(sleep_wait=False, quick_scan=True)
            if not md5sum:
                sleep(.1)
                continue

            try:
                self.quick_scan(md5sum)
            except Exception as e:
                # we should never have an exception at this point.
                log.error("Error during quick_scan of md5sum %s: %s: %s" % (md5sum, e.__class__.__name__, str(e)))


class DeepAnalysisThread(BinaryConsumerThread):
    def deep_analysis(self, md5sum):
        try:
            res = self.provider.check_result_for(md5sum)
            if type(res) == AnalysisResult:
                self.save_successful_analysis(md5sum, res)
                return
            # intentionally fall through if we return None from check_result_for...
        except AnalysisTemporaryError as e:
            self.save_unsuccessful_analysis(md5sum, e)
        except AnalysisPermanentError as e:
            self.save_unsuccessful_analysis(md5sum, e)
        except Exception as e:
            self.save_unsuccessful_analysis(md5sum, AnalysisTemporaryError(message="Exception in check_result_for",
                                                                           extended_message=traceback.format_exc()))
            return

        # we did not get a valid AnalysisResult from check_result_for, let's pull the binary down and scan it.

        try:
            z = StringIO(self.cb.binary(md5sum))
        except Exception as e:
            self.save_unsuccessful_analysis(md5sum, AnalysisTemporaryError(message="Binary not available in Cb",
                                                                           retry_in=60))
            return

        try:
            zf = ZipFile(z)
            fp = zf.open('filedata')
        except Exception as e:
            self.save_unsuccessful_analysis(md5sum, AnalysisPermanentError(message="Zip file corrupt",
                                                                           extended_message=traceback.format_exc()))
            return

        try:
            res = self.provider.analyze_binary(md5sum, fp)
        except AnalysisTemporaryError as e:
            self.save_unsuccessful_analysis(md5sum, e)
        except AnalysisPermanentError as e:
            self.save_unsuccessful_analysis(md5sum, e)
        except Exception as e:
            self.save_unsuccessful_analysis(md5sum, AnalysisTemporaryError(message="Exception in analyze_binary",
                                                                           extended_message=traceback.format_exc()))
        else:
            self.save_successful_analysis(md5sum, res)

    def run(self):
        while not self.done:
            md5sum = self.queue.get(sleep_wait=False)
            if not md5sum:
                sleep(.1)
                continue

            try:
                self.deep_analysis(md5sum)
            except Exception as e:
                # we should never have an exception at this point.
                log.error("Error during deep_scan of md5sum %s: %s: %s" % (md5sum, e.__class__.__name__, str(e)))
