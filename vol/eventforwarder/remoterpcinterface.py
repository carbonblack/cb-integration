from supervisor.rpcinterface import SupervisorNamespaceRPCInterface
import xmlrpc.client as xclient 

class RemoteConnectorInterface:

    @property
    def _xclient(self):
        if self.__xclient == None:
            try:
                self.__xclient = xclient.ServerProxy('http://event-forwarder:9001')
            finally:
                return self.__xclient
        else:
            return self.__xclient

    def __init__(self,supervisord):
        self.__xclient = None
        self.supervisord = supervisord

    def getAllProcessInfo(self):
        #return self.xclient.system.listMethods()
        return []


def make_custom_rpcinterface(supervisord):
    return RemoteConnectorInterface(supervisord)
