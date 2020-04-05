import os
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.ciphers.aead import AESCCM

'''
'''

"""
https://cryptography.io/en/latest/hazmat/primitives/aead/

Authenticated encryption with associated data (AEAD) are encryption schemes which provide both confidentiality 
and integrity for their ciphertext. They also support providing integrity for associated data which is not encrypted.
"""
data = b"a secret message"
aad = b"authenticated but unencrypted data"
key = ChaCha20Poly1305.generate_key()
chacha = ChaCha20Poly1305(key)
nonce = os.urandom(12)
ct = chacha.encrypt(nonce, data, aad)
chacha.decrypt(nonce, ct, aad)


"""
The AES-GCM construction is composed of the AES block cipher utilizing Galois Counter Mode (GCM).
"""
data = b"a secret message"
aad = b"authenticated but unencrypted data"
key = AESGCM.generate_key(bit_length=128)
aesgcm = AESGCM(key)
nonce = os.urandom(12)
ct = aesgcm.encrypt(nonce, data, aad)
aesgcm.decrypt(nonce, ct, aad)


"""
The AES-CCM construction is composed of the AES block cipher utilizing Counter with CBC-MAC (CCM) 
(specified in RFC 3610).
"""
data = b"a secret message"
aad = b"authenticated but unencrypted data"
key = AESCCM.generate_key(bit_length=128)
aesccm = AESCCM(key)
nonce = os.urandom(13)
ct = aesccm.encrypt(nonce, data, aad)
aesccm.decrypt(nonce, ct, aad)

"""
Asymmetric cryptography is a branch of cryptography where a secret key can be divided into two parts, 
a public key and a private key. The public key can be given to anyone, trusted or not, while the private key must 
be kept secret (just like the key in symmetric cryptography).

Asymmetric cryptography has two primary use cases: authentication and confidentiality. Using asymmetric cryptography,
 messages can be signed with a private key, and then anyone with the public key is able to verify that the message was 
 created by someone possessing the corresponding private key. This can be combined with a proof of identity system to 
 know what entity (person or group) actually owns that private key, providing authentication.

Encryption with asymmetric cryptography works in a slightly different way from symmetric encryption. 
Someone with the public key is able to encrypt a message, providing confidentiality, and then only the person in 
possession of the private key is able to decrypt it.
"""

