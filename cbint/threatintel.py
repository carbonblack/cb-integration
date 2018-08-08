import logging

from cbint.integration import Integration

logger = logging.getLogger(__name__)


class ThreatIntel(Integration):
    def __init__(self):
        super().__init__()
        self.summary = ''
        self.tech_data = ''
        self.provider_url = ''
        self.icon_path = ''
        self.display_name = ''
        self.category = ''
        self.feedinfo = None
        self.reports = []

    def validate_ext_config(self):
        pass