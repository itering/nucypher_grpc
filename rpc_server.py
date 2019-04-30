from concurrent import futures
import time
import logging
import grpc
from libs import rpc_api, rpc_pb2, rpc_pb2_grpc
from umbral import keys, config
from umbral.curve import Curve

_ONE_DAY_IN_SECONDS = 60 * 60 * 24


class ReProxy(rpc_pb2_grpc.ReProxyServicer):

    def Encrypt(self, request, context):
        encrypt_text, capsule = rpc_api.UmbralApi.encrypt_by_pk(
            keys.UmbralPublicKey.from_bytes(bytes.fromhex(request.pk)),
            str.encode(request.text))
        return rpc_pb2.EncryptReply(message=encrypt_text.hex(), capsule=capsule.to_bytes().hex())

    def Decrypt(self, request, context):
        sk = keys.UmbralPrivateKey.from_bytes(bytes.fromhex(request.sk))
        encrypt_text = bytes.fromhex(request.text)
        capsule = rpc_api.pre.Capsule.from_bytes(bytes.fromhex(request.capsule),
                                                 rpc_api.pre.UmbralParameters(Curve(714)))
        text = rpc_api.UmbralApi.decrypt_by_sk(sk, encrypt_text, capsule)
        return rpc_pb2.EncryptReply(text=text.hex())

    def GetKFlags(self, request, context):
        sk = keys.UmbralPrivateKey.from_bytes(bytes.fromhex(request.sk))
        cpk = keys.UmbralPublicKey.from_bytes(bytes.fromhex(request.pk))
        k_frags, proxy_pk = rpc_api.UmbralApi.generate_k_flags(sk, cpk)
        return rpc_pb2.EncryptReply(flags=k_frags, text=proxy_pk.hex())

    def Capsule(self, request, context):
        capsule = rpc_api.pre.Capsule.from_bytes(bytes.fromhex(request.capsule),
                                                 rpc_api.pre.UmbralParameters(Curve(714)))
        flags = request.flags
        cpk = keys.UmbralPublicKey.from_bytes(bytes.fromhex(request.dpk))
        rpk = keys.UmbralPublicKey.from_bytes(bytes.fromhex(request.rpk))
        ppk = keys.UmbralPublicKey.from_bytes(bytes.fromhex(request.ppk))
        text = rpc_api.UmbralApi.capsule_attach(capsule, flags, cpk, rpk, ppk)
        return rpc_pb2.EncryptReply(text=text.hex())


def serve():
    config.set_default_curve()
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=10))
    rpc_pb2_grpc.add_ReProxyServicer_to_server(ReProxy(), server)
    server.add_insecure_port('[::]:50051')
    server.start()
    try:
        while True:
            time.sleep(_ONE_DAY_IN_SECONDS)
    except KeyboardInterrupt:
        server.stop(0)


if __name__ == '__main__':
    logging.basicConfig()
    serve()
