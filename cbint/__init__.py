import logging

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

log_formatter = logging.Formatter('%(asctime)s %(levelname)s %(funcName)s(%(lineno)d) %(message)s')
stream_handler = logging.StreamHandler()
stream_handler.setFormatter(log_formatter)

logger.addHandler(logging.StreamHandler())
