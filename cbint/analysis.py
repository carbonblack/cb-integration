import logging

logger = logging.getLogger(__name__)


class AnalysisResult(object):
    def __init__(self, score=0, short_result='', long_result='', last_error_msg='', stop_future_scans=False):
        self.short_result = short_result
        self.long_result = long_result
        self.last_error_msg = last_error_msg
        self.score = score
        self.stop_future_scans = stop_future_scans
