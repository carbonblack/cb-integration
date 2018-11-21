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
        try:
            self.clientToDaemon.force_rescan_all()
            return True
        except Exception as e:
            return False

    def getResultFor(self,md5):
        try:
            return self.clientToDaemon.get_result_for(md5)
        except Exception as e:
            return {"error":str(e)}

    def executeBinaryQuery(self,query):
        try:
            return self.clientToDaemon.executeBinaryQuery(query)
        except Exception as e:
            return {"error":str(e)}

    def listYaraRules(self):
        return self.clientToDaemon.get_yara_rules()

    def getStatistics(self):
        try:
            return self.clientToDaemon.getStatistics()
        except Exception as e:
            return {"error":str(e)}

    def getFeedDump(self):
        try:
            feed_dump =  self.clientToDaemon.get_feed_dump()
            reports = feed_dump.get('reports',{})
            ret = {}
            for report in reports:
                for hash in report['iocs']['md5']:
                    ret[hash]=report['score']
            return ret

        except Exception as e:
             return {"error":str(e)}

    def getBinaryQueue(self):
        try:
            return self.clientToDaemon.getBinaryQueue()
        except Exception as e:
            return {"error":str(e)}

    #def uploadYaraRule(self):
    #    return True


def make_custom_rpcinterface(supervisord):
    return CbFeedInterface(supervisord)