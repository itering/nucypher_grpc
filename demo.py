import random
from umbral import pre, keys, config, signing


class BColors:
    OK = '\033[94m'
    END = '\033[0m'


# client 
config.set_default_curve()
alice_private_key = keys.UmbralPrivateKey.gen_key()
alice_public_key = alice_private_key.get_pubkey()
print(alice_private_key.to_bytes().hex(), alice_public_key.to_bytes().hex())
print(BColors.OK + "alice generate private key" + BColors.END)


# server
plaintext = b'Proxy Re-encryption is cool!'
encryptText, capsule = pre.encrypt(alice_public_key, plaintext)
print("encryptText", encryptText.hex())

# escrow
bobs_private_key = keys.UmbralPrivateKey.gen_key()
bobs_public_key = bobs_private_key.get_pubkey()
print(BColors.OK + "bobs generate private key" + BColors.END)

bob_capsule = capsule

proxy_signing_key = keys.UmbralPrivateKey.gen_key()
proxy_public_key = proxy_signing_key.get_pubkey()
alice_signer = signing.Signer(private_key=proxy_signing_key)

print(BColors.OK + "Alice Generate a new key and signer" + BColors.END)

kFrags = pre.generate_kfrags(delegating_privkey=alice_private_key,
                             signer=alice_signer,
                             receiving_pubkey=bobs_public_key,
                             threshold=10,
                             N=20)

print(BColors.OK + "She uses her private key, and Bob's public key, she sets 20 total shares" + BColors.END)

kFrags = random.sample(kFrags, 10)
print(type(kFrags))
print(BColors.OK + "choose random 10 shares" + BColors.END)

bob_capsule.set_correctness_keys(delegating=alice_public_key,
                                 receiving=bobs_public_key,
                                 verifying=proxy_public_key)

cFrags = list()
for kFrag in kFrags:
    cFrags.append(pre.reencrypt(kfrag=kFrag, capsule=bob_capsule))

for cFrag in cFrags:
    bob_capsule.attach_cfrag(cFrag)

bob_clearText = pre.decrypt(ciphertext=encryptText, capsule=bob_capsule, decrypting_key=bobs_private_key)
