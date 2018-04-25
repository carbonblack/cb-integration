import configparser
import logging
import cbsdk.globals

logger = logging.getLogger(__name__)


class Integration(object):
    """
    Base Class
    """
    def __init__(self):
        self.summary = ''
        self.tech_data = ''
        self.provider_url = ''
        self.icon_path = ''
        self.display_name = ''
        self.category = ''
        self.feedinfo = None
        self.reports = []

        self.validate_base_config()
        pass

    def validate_base_config(self):
        cfg_parser = configparser.ConfigParser().read('integration.conf')
        cbsdk.globals.g_config = cfg_parser
