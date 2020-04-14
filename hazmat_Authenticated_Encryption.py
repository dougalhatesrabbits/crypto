import os
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.ciphers.aead import AESCCM
'''
https://cryptography.io/en/latest/hazmat/primitives/aead/

Authenticated encryption with associated data (AEAD) are encryption schemes which provide both confidentiality and
integrity for their ciphertext. They also support providing integrity for associated data which is not encrypted.

'''

def chacha_streamcipher():
    """
    The ChaCha20Poly1305 construction is defined in RFC 7539 section 2.8. It is a stream cipher combined with a MAC
    that offers strong integrity guarantees.
    :return:
    """
    data = b"a secret message"
    print(data)
    aad = b"authenticated but unencrypted data"
    print(aad)
    key = ChaCha20Poly1305.generate_key()
    print(key)
    chacha = ChaCha20Poly1305(key)
    print(chacha)
    nonce = os.urandom(12)
    print(nonce)
    ct = chacha.encrypt(nonce, data, aad)
    print(ct)
    print(chacha.decrypt(nonce, ct, aad))


def aesgcm_cipher():
    """
    The AES-GCM construction is composed of the AES block cipher utilizing Galois Counter Mode (GCM).

    :return:
    """
    data = b"a secret message"
    print(data)
    aad = b"authenticated but unencrypted data"
    print(aad)
    key = AESGCM.generate_key(bit_length=128)
    print(key)
    aesgcm = AESGCM(key)
    print(aesgcm)
    nonce = os.urandom(12)
    print(nonce)
    ct = aesgcm.encrypt(nonce, data, aad)
    print(ct)
    print(aesgcm.decrypt(nonce, ct, aad))


def aesccm_cipher():
    """
    The AES-CCM construction is composed of the AES block cipher utilizing Counter with CBC-MAC (CCM)
    (specified in RFC 3610).

    :return:
    """
    data = b"a secret message"
    print(data)
    aad = b"authenticated but unencrypted data"
    print(aad)
    key = AESCCM.generate_key(bit_length=128)
    print(key)
    aesccm = AESCCM(key)
    print(aesccm)
    nonce = os.urandom(13)
    print(nonce)
    ct = aesccm.encrypt(nonce, data, aad)
    print(ct)
    print(aesccm.decrypt(nonce, ct, aad))


def main():
    chacha_streamcipher()
    aesgcm_cipher()
    aesccm_cipher()

if __name__ == "__main__":
    # execute only if run as a script
    main()