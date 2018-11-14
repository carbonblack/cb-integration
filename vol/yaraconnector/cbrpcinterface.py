import logging
from supervisor.rpcinterface import SupervisorNamespaceRPCInterface
import xmlrpc.client
import cbint.globals

class CbFeedInterface:

    def __init__(self, supervisord):
        self.supervisord = supervisord
        self.clientToDaemon = xmlrpc.client.ServerProxy('http://127.0.0.1:9002')

    def listAllMethods(self):
        return self.clientToDaemon.system.listMethods()

    def forceRescanAll(self):
        self.clientToDaemon.forceRescanAll()
        return True

    def getResultFor(self,md5):
        return self.clientToDaemon.get_result_for(md5)

    def executeBinaryQuery(self,query):
        return self.clientToDaemon.executeBinaryQuery(query)

    def listYaraRules(self):
        return self.clientToDaemon.get_yara_rules()

    def getStatistics(self):
        return self.clientToDaemon.getStatistics()

    def getYaraRulesDirectory(self):
        return self.clientToDaemon.get_yara_rules_directory()

    def getDebugLogs(self):
        return self.clientToDaemon.getDebugLogs()

    def getFeed(self):
        return self.clientToDaemon.getFeed()

    def getFeedDump(self):
        return self.clientToDaemon.getFeedDump()

    def getBinaryQueue(self):
        return self.clientToDaemon.getBinaryQueue()

    def uploadYaraRule(self):
        return True


def make_custom_rpcinterface(supervisord):
    return CbFeedInterface(supervisord)