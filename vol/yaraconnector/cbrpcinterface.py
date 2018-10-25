import logging
from supervisor.rpcinterface import SupervisorNamespaceRPCInterface
import xmlrpc.client

class CbFeedInterface:

    def __init__(self, supervisord):
        self.supervisord = supervisord
        self.clientToDaemon = xmlrpc.client.ServerProxy('http://localhost:9002')

    def listMethods(self):
        return self.clientToDaemon.system.listMethods()

    def forceRescanAll(self,name):
        self.clientToDaemon.forceRescanAll()



def make_custom_rpcinterface(supervisord):
    return CbFeedInterface(supervisord)