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
        self.clientToDaemon.force_rescan_all()
        return True

    def getResultFor(self,md5):
        return self.clientToDaemon.get_result_for(md5)

    def executeBinaryQuery(self,query):
        return self.clientToDaemon.executeBinaryQuery(query)

    def listYaraRules(self):
        return self.clientToDaemon.get_yara_rules()

    def getStatistics(self):
        return self.clientToDaemon.getStatistics()

    def getFeedDump(self):
        feed_dump =  self.clientToDaemon.get_feed_dump()
        return feed_dump.get('reports',["NO REPORTS YET"])

    def getBinaryQueue(self):
        return self.clientToDaemon.getBinaryQueue()

    #def uploadYaraRule(self):
    #    return True


def make_custom_rpcinterface(supervisord):
    return CbFeedInterface(supervisord)