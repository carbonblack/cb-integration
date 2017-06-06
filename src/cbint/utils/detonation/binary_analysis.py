import threading
import datetime
import traceback
from time import sleep
from zipfile import ZipFile
from cStringIO import StringIO
import time
import logging
import dateutil.parser

from cbapi.response import Binary

log = logging.getLogger(__name__)


def to_cb_time(dt):
    return dt.strftime('%Y-%m-%dT%H:%M:%S')


class CbAPIProducerThread(threading.Thread):
    def __init__(self, work_queue, cb, name, max_rows=None, sleep_between=60, rate_limiter=0.1, stop_when_done=False,
                 filter_spec=''):
        threading.Thread.__init__(self)
        self.daemon = True

        self.queue = work_queue
        self.done = False
        self.cb = cb
        self.feed_name = name
        self.sleep_between = sleep_between
        self.max_rows = max_rows
        self.rate_limiter = rate_limiter
        self.stop_when_done = stop_when_done
        self.filter_spec = filter_spec

        now = getattr(self, 'default_start_time', datetime.datetime.utcnow())
        now = to_cb_time(now)

        self.start_time_key = self.__class__.__name__ + '_start_time'
        self.start_time = dateutil.parser.parse(self.queue.get_value(self.start_time_key, now))

    def stop(self):
        self.done = True

    @property
    def query_string(self):
        return self.filter_spec

    @property
    def query_sort(self):
        return "server_added_timestamp desc"

    def run(self):
        log.info("Starting %s with start_time=%s" % (self.start_time_key, self.start_time))
        cur_timestamp = to_cb_time(self.start_time)
        self.queue.set_value(self.start_time_key, cur_timestamp)

        while not self.done:
            # TODO: retry logic - make sure we don't bomb out if this fails
            log.debug("Querying cb for binaries matching '%s'" % self.query_string)
            try:

                binary_query = self.cb.select(Binary).where(self.query_string)
                for i, binary in enumerate(binary_query):
                    # for i, binary in enumerate(self.cb.binary_search_iter(self.query_string,
                    #                                                      sort=self.query_sort)):
                    if self.done:
                        return

                    # TODO: keep track of server_added_timestamp if we have it, and use that to filter next time
                    if not self.queue.notify_binary_available(binary.md5):
                        pass
                        # print 'md5 %s already tracked' % (binary['md5'],)

                    sleep(self.rate_limiter)  # no need to flood the Cb server or ourselves with binaries
                    cur_timestamp = binary.server_added_timestamp

                    if self.max_rows and i > self.max_rows:
                        break

                    if i % 100 == 0:
                        self.queue.set_value(self.start_time_key, cur_timestamp)

            except Exception as e:
                log.error("Error during binary enumeration: %s. Sleeping for %f seconds and retrying."
                          % (str(e), self.sleep_between))

            self.queue.set_value(self.start_time_key, cur_timestamp)
            self.start_time = dateutil.parser.parse(cur_timestamp)

            if self.stop_when_done:
                self.done = True
            else:
                sleep(self.sleep_between)


class CbAPIUpToDateProducerThread(CbAPIProducerThread):
    def __init__(self, *args, **kwargs):
        self.default_start_time = kwargs.pop('start_time', datetime.datetime.utcnow())
        super(CbAPIUpToDateProducerThread, self).__init__(*args, **kwargs)

    @property
    def query_string(self):
        if self.start_time:
            return "server_added_timestamp:[%s TO *] -alliance_score_%s:* %s" % (to_cb_time(self.start_time),
                                                                                 self.feed_name,
                                                                                 self.filter_spec)
        else:
            return "-alliance_score_%s:* %s" % (self.feed_name, self.filter_spec)

    @property
    def query_sort(self):
        return "server_added_timestamp asc"


class CbAPIHistoricalProducerThread(CbAPIProducerThread):
    def __init__(self, *args, **kwargs):
        self.default_start_time = kwargs.pop('start_time', datetime.datetime.utcnow())
        super(CbAPIHistoricalProducerThread, self).__init__(*args, **kwargs)

    @property
    def query_string(self):
        if self.start_time:
            return "server_added_timestamp:[* TO %s] -alliance_score_%s:* %s" % (to_cb_time(self.start_time),
                                                                                 self.feed_name,
                                                                                 self.filter_spec)
        else:
            return "-alliance_score_%s:* %s" % (self.feed_name, self.filter_spec)

    @property
    def query_sort(self):
        return "server_added_timestamp desc"


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
    def __init__(self, message="", extended_message="", analysis_version=1, score=0, link=None):
        self.score = score
        self.message = message
        self.extended_message = extended_message
        self.analysis_version = analysis_version
        self.link = link


class AnalysisInProgress(object):
    def __init__(self, message="", extended_message="", retry_in=60, analysis_version=1):
        self.message = message
        self.extended_message = extended_message
        self.retry_in = retry_in
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
        self.daemon = True

        self.database_arbiter = work_queue
        self.done = False
        self.provider = provider
        self.cb = cb
        self.dirty_event = dirty_event

    def stop(self):
        self.done = True

    def save_successful_analysis(self, md5sum, analysis_result):
        self.database_arbiter.mark_as_analyzed(md5sum, True, analysis_result.analysis_version, analysis_result.message,
                                               analysis_result.extended_message, score=analysis_result.score,
                                               link=analysis_result.link)
        log.info("Analyzed md5sum: %s - score %d%s. Refreshing feed." % (md5sum, analysis_result.score,
                                                                         " (%s)" % analysis_result.message if analysis_result.message else ""))
        self.dirty_event.set()

    def save_unsuccessful_analysis(self, md5sum, e):
        if type(e) == AnalysisTemporaryError:
            retry_in_seconds = int(e.retry_in)
            self.database_arbiter.mark_as_analyzed(md5sum, False, e.analysis_version, e.message, e.extended_message,
                                                   retry_at=datetime.datetime.utcnow() + datetime.timedelta(
                                                       seconds=retry_in_seconds))
            log.error("Temporary error analyzing md5sum %s: %s (%s). Will retry in %d seconds." % (md5sum,
                                                                                                   e.message,
                                                                                                   e.extended_message,
                                                                                                   retry_in_seconds))
        elif type(e) == AnalysisPermanentError:
            self.database_arbiter.mark_as_analyzed(md5sum, False, e.analysis_version, e.message, e.extended_message)
            log.error("Permanent error analyzing md5sum %s: %s (%s)." % (md5sum,
                                                                         e.message,
                                                                         e.extended_message))
        else:
            self.database_arbiter.mark_as_analyzed(md5sum, False, 0, "%s: %s" % (e.__class__.__name__, e.message),
                                                   "%s" % traceback.format_exc())
            log.error("Unknown error analyzing md5sum %s: %s (%s)." % (md5sum,
                                                                       e.__class__.__name__,
                                                                       e.message))

    def save_empty_quick_scan(self, md5sum):
        self.database_arbiter.mark_quick_scan_complete(md5sum)


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
        for md5sum in self.database_arbiter.binaries():
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
            elif type(res) == AnalysisInProgress:
                raise AnalysisTemporaryError(message=res.message, retry_in=res.retry_in)
            # intentionally fall through if we return None from check_result_for...
            log.debug("deep_analysis could not shortcut analysis of %s, proceeding..." % md5sum)
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
            start_dl_time = time.time()

            binary = self.cb.select(Binary, md5sum)
            fp = StringIO(binary.file.read())

            end_dl_time = time.time()
            log.debug("%s: Took %0.3f seconds to download the file" % (md5sum, end_dl_time - start_dl_time))
        except Exception as e:
            self.save_unsuccessful_analysis(md5sum, AnalysisTemporaryError(message="Binary not available in Cb",
                                                                           retry_in=60))
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
        for md5sum in self.database_arbiter.binaries():
            log.debug("deep_analysis retrieved md5sum %s from database_arbiter" % md5sum)
            try:
                self.deep_analysis(md5sum)
            except Exception as e:
                # we should never have an exception at this point.
                log.error("Error during deep_scan of md5sum %s: %s: %s" % (md5sum, e.__class__.__name__, str(e)))
