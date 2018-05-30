import configparser
import logging
import os

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
        self.validate_base_config()
        pass

    def validate_base_config(self):
        cfg_parser = configparser.ConfigParser().read(
            os.path.join(
                self.get_volume_directory(),
                'integration.conf'))

        cbint.globals.g_config = cfg_parser

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
            cbint.globals.g_volume_directory = os.path.join("/conf", self.name)
        else:
            #
            # For Debugging outside of Docker
            #
            cbint.globals.g_base_directory = os.path.join(os.path.dirname(__file__), "..")
            cbint.globals.g_volume_directory = os.path.join(os.path.dirname(__file__), "../conf")
        logger.debug(f'base directory: {cbint.globals.g_base_directory}')
        logger.debug(f'volume directory: {cbint.globals.g_volume_directory}')

    def get_volume_directory(self):
        return cbint.globals.g_volume_directory

    def get_base_directory(self):
        return cbint.globals.g_base_directory
