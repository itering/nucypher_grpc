from umbral import pre, keys, signing
import random


class UmbralApi(object):

    @classmethod
    def encrypt_by_pk(cls, pk: keys.UmbralPublicKey, text: bytes):
        encrypt_text, capsule = pre.encrypt(pk, text)
        return encrypt_text, capsule

    @classmethod
    def decrypt_by_sk(cls, sk: keys.UmbralPrivateKey, encrypt_text: bytes, capsule: pre.Capsule):
        decrypt_text = pre.decrypt(ciphertext=encrypt_text, capsule=capsule, decrypting_key=sk)
        return decrypt_text

    @classmethod
    def generate_k_flags(cls, sk: keys.UmbralPrivateKey, escrow_pk: keys.UmbralPublicKey):
        proxy_signing_key = keys.UmbralPrivateKey.gen_key()
        proxy_public_key = proxy_signing_key.get_pubkey()
        signer = signing.Signer(private_key=proxy_signing_key)
        k_frags = pre.generate_kfrags(delegating_privkey=sk,
                                      signer=signer,
                                      receiving_pubkey=escrow_pk,
                                      threshold=10,
                                      N=20)
        k_frags = random.sample(k_frags, 10)
        return k_frags, proxy_public_key.to_bytes()

    @classmethod
    def capsule_attach(cls, capsule: pre.Capsule, k_frags, d_pk: keys.UmbralPublicKey, r_pk: keys.UmbralPublicKey,
                       p_pk: keys.UmbralPublicKey):
        capsule.set_correctness_keys(delegating=d_pk,
                                     receiving=r_pk,
                                     verifying=p_pk)

        c_frags = list()
        for kFrag in k_frags:
            c_frags.append(pre.reencrypt(kfrag=kFrag, capsule=capsule))

        for cFrag in c_frags:
            capsule.attach_cfrag(cFrag)
        return capsule.to_bytes()


class EscrowApi(object):

    def __init__(self, pair: keys.UmbralPrivateKey):
        self.pair = pair
        pass

    """
    @sk from storage
    General UmbralPrivate from sk bytes escrow account
    """

    @classmethod
    def gen_by_sk(cls, sk: bytes) -> keys.UmbralPrivateKey:
        private_key = keys.UmbralPrivateKey.from_bytes(sk)
        return private_key

    """
    @sk from storage
    General a UmbralPrivate  escrow account
    """

    @classmethod
    def gen_new(cls) -> keys.UmbralPrivateKey:
        private_key = keys.UmbralPrivateKey.gen_key()
        return private_key
