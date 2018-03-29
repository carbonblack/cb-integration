from concurrent import futures

import grpc
import logging
import traceback

import cbint.cbint_pb2 as cbint_pb2
import cbint.cbint_pb2_grpc as cbint_pb2_grpc

logger = logging.getLogger(__name__)


class RpcServer(cbint_pb2_grpc.DetonationServicer):
    def get_status(self, request, context):
        return cbint_pb2.StatusResponse(message='Hello, %s!' % request.name)

    def start(self, port):
        try:
            self.server = grpc.server(futures.ThreadPoolExecutor(max_workers=10))
            cbint_pb2_grpc.add_DetonationServicer_to_server(self, self.server)
            self.server.add_insecure_port(f'[::]:{port}')
            self.server.start()
        except:
            logger.error(traceback.format_exc())

    def stop(self):
        self.server.stop()
