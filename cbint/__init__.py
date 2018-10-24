import logging
from supervisor.rpcinterface import SupervisorNamespaceRPCInterface
import cbint.globals
class CbFeedInterface:
    def __init__(self, supervisord):
        self.supervisord = supervisord
        self.retries = 3

    def forceRescanAll(self,name):
        cbint.globals.g_integration.force_rescan_all()
    '''
    def startProcessOrRetry(self, name, wait=True):
        interface = SupervisorNamespaceRPCInterface(self.supervisord)
        retry = 0

        while not interface.startProcess(name) or retry < self.retries:
            retry = retry + 1
            '''



# this is not used in code but referenced via an entry point in the conf file
def make_custom_rpcinterface(supervisord):
    return CbFeedInterface(supervisord)