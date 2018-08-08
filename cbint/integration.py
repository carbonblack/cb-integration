import configparser
import logging
import os
import sys
from logging.handlers import RotatingFileHandler

import cbint.globals

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)


class Integration(object):
    """
    Base Class
    """

    def __init__(self, name=""):
        self.summary = ''
        self.tech_data = ''
        self.provider_url = ''
        self.icon_path = ''
        self.display_name = ''
        self.category = ''
        self.feedinfo = None
        self.reports = []
        self.name = name

        self.set_connector_directory()
        self.set_logging()
        self.validate_general_config()

    def set_logging(self):
        if self.inside_docker():
            log_file = os.path.join(cbint.globals.g_volume_directory, "{0}.log".format(self.name))
        else:
            log_file = "{0}.log".format(self.name)

        log_formatter = logging.Formatter('%(asctime)s %(levelname)s %(funcName)s(%(lineno)d) %(message)s')
        file_handler = RotatingFileHandler(log_file, maxBytes=5 * 1024 * 1024, backupCount=5)
        file_handler.setFormatter(log_formatter)

        logger = logging.getLogger("cbint")
        logger.addHandler(file_handler)

    def validate_general_config(self):
        cfg_parser = configparser.ConfigParser()
        cfg_parser.read(os.path.join(self.get_volume_directory(), self.name, "{0}.conf".format(self.name)))

        cbint.globals.g_config = cfg_parser

        if 'general' not in cfg_parser.sections():
            logger.error('config file requires a general section')
            # TODO add more validation here
            sys.exit(-1)

        cbint.globals.g_config = cfg_parser['general']

    def inside_docker(self):
        """
        :return: if we are running inside docker
        """
        if os.path.exists('/.dockerenv'):
            return True
        else:
            return False

    def set_connector_directory(self):
        if self.inside_docker():
            cbint.globals.g_base_directory = "/"
            cbint.globals.g_volume_directory = "/vol"
        else:
            #
            # For Debugging outside of Docker
            #
            cbint.globals.g_base_directory = os.path.join(os.path.dirname(__file__), "..")
            cbint.globals.g_volume_directory = os.path.join(os.path.dirname(__file__), "../vol")
        logger.debug(f'base directory: {cbint.globals.g_base_directory}')
        logger.debug(f'volume directory: {cbint.globals.g_volume_directory}')

    def get_volume_directory(self):
        return cbint.globals.g_volume_directory

    def get_base_directory(self):
        return cbint.globals.g_base_directory
