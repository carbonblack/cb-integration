import grpc
import cbint.cbint_pb2
import cbint.cbint_pb2_grpc


def main():
    channel = grpc.insecure_channel('localhost:50051')
    stub = cbint.cbint_pb2_grpc.DetonationStub(channel)
    response = stub.get_status(cbint.cbint_pb2.Status(name='you'))
    print("Greeter client received: " + response.message)


if __name__ == '__main__':
    main()
