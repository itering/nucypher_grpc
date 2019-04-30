from __future__ import print_function
import logging
import grpc
from libs import rpc_pb2, rpc_pb2_grpc


def run():
    with grpc.insecure_channel('localhost:50051') as channel:
        stub = rpc_pb2_grpc.ReProxyStub(channel)
        pk = "039b471f5413e2d2bf317661463ca24b62f0b821c948d282f7e735a62e3bdaeb9e"
        text = "thistext"
        response = stub.Encrypt(rpc_pb2.EncryptRequest(pk=pk, text=text))
    print("get Encrypt text " + response.message)
    print("get capsule " + response.capsule)


if __name__ == '__main__':
    logging.basicConfig()
    run()
