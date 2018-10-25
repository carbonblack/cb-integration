import logging
from supervisor.rpcinterface import SupervisorNamespaceRPCInterface
import xmlrpc.client
import cbint.globals

class CbFeedInterface:

    def __init__(self, supervisord):
        self.supervisord = supervisord
        self.clientToDaemon = xmlrpc.client.ServerProxy('http://localhost:9002')

    def listAllMethods(self):
        return self.clientToDaemon.system.listMethods()

    def hello(self):
        return "Hello world"

    def forceRescanAll(self):
        self.clientToDaemon.forceRescanAll()

    def listYaraRules(self):
        self.clientToDaemon.get_yara_rules()

    def getStatistics(self):
        self.clientToDaemon.getStatistics()

def make_custom_rpcinterface(supervisord):
    return CbFeedInterface(supervisord)