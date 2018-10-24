import logging
from supervisor.rpcinterface import SupervisorNamespaceRPCInterface
import cbint.globals
class CbFeedInterface:
    def __init__(self, supervisord):
        self.supervisord = supervisord
        self.retries = 3

    def forceRescanAll(self,name):
        cbint.globals.g_integration.force_rescan_all()

def make_custom_rpcinterface(supervisord):
    return CbFeedInterface(supervisord)