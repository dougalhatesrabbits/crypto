from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.asymmetric import x25519
'''
https://cryptography.io/en/latest/hazmat/primitives/asymmetric/

Asymmetric algorithms

Asymmetric cryptography is a branch of cryptography where a secret key can be divided into two parts, a public key and
a private key. The public key can be given to anyone, trusted or not, while the private key must be kept secret
(just like the key in symmetric cryptography).

Asymmetric cryptography has two primary use cases: authentication and confidentiality. Using asymmetric cryptography,
messages can be signed with a private key, and then anyone with the public key is able to verify that the message was
created by someone possessing the corresponding private key. This can be combined with a proof of identity system to
know what entity (person or group) actually owns that private key, providing authentication.

Encryption with asymmetric cryptography works in a slightly different way from symmetric encryption. Someone with the
public key is able to encrypt a message, providing confidentiality, and then only the person in possession of the
private key is able to decrypt it.
'''

def ed25519_signing():
    """
    Ed25519 is an elliptic curve signing algorithm using EdDSA and Curve25519. If you do not have legacy
    interoperability concerns then you should strongly consider using this signature algorithm.
    :return:
    """
    private_key = Ed25519PrivateKey.generate()
    print(private_key)
    signature = private_key.sign(b"my authenticated message")
    print(signature)
    public_key = private_key.public_key()
    print(public_key)
    # Raises InvalidSignature if verification fails
    print(public_key.verify(signature, b"my authenticated message"))


def ed25519_generate_key():
    """
    Generate an Ed25519 private key.
    :return:
    """
    private_key = ed25519.Ed25519PrivateKey.generate()
    print(private_key)
    private_bytes = private_key.private_bytes(
        encoding = serialization.Encoding.Raw,
        format = serialization.PrivateFormat.Raw,
        encryption_algorithm = serialization.NoEncryption()
    )
    print(private_bytes)
    loaded_private_key = ed25519.Ed25519PrivateKey.from_private_bytes(private_bytes)
    print(loaded_private_key)


def x25519_exchange():
    """
    X25519 key exchange

    X25519 is an elliptic curve Diffie-Hellman key exchange using Curve25519. It allows two parties to jointly agree on
    a shared secret using an insecure channel.

    Exchange Algorithm

    For most applications the shared_key should be passed to a key derivation function. This allows mixing of additional
    information into the key, derivation of multiple keys, and destroys any structure that may be present.

    :return:
    """
    # Generate a private key for use in the exchange.
    private_key = X25519PrivateKey.generate()
    print(private_key)
    # In a real handshake the peer_public_key will be received from the
    # other party. For this example we'll generate another private key and
    # get a public key from that. Note that in a DH handshake both peers
    # must agree on a common set of parameters.
    peer_public_key = X25519PrivateKey.generate().public_key()
    print(peer_public_key)
    shared_key = private_key.exchange(peer_public_key)
    print(shared_key)
    # Perform key derivation.
    derived_key = HKDF(
        algorithm = hashes.SHA256(),
        length = 32,
        salt = None,
        info = b'handshake data',
        backend = default_backend()
    ).derive(shared_key)
    print(derived_key)
    # For the next handshake we MUST generate another private key.
    private_key_2 = X25519PrivateKey.generate()
    print(private_key_2)
    peer_public_key_2 = X25519PrivateKey.generate().public_key()
    print(peer_public_key_2)
    shared_key_2 = private_key_2.exchange(peer_public_key_2)
    print(shared_key_2)
    derived_key_2 = HKDF(
        algorithm = hashes.SHA256(),
        length = 32,
        salt = None,
        info = b'handshake data',
        backend = default_backend()
    ).derive(shared_key_2)
    print(derived_key_2)


def x25519_generate_private():
    """
    Generate an X25519 private key
    :return:
    """
    private_key = x25519.X25519PrivateKey.generate()
    print(private_key)
    private_bytes = private_key.private_bytes(
        encoding = serialization.Encoding.Raw,
        format = serialization.PrivateFormat.Raw,
        encryption_algorithm = serialization.NoEncryption()
    )
    print(private_bytes)
    loaded_private_key = x25519.X25519PrivateKey.from_private_bytes(private_bytes)
    print(loaded_private_key)


def x255219_generate_public():
    """

    :return:
    """
    private_key = x25519.X25519PrivateKey.generate()
    print(private_key)
    public_key = private_key.public_key()
    print(public_key)
    public_bytes = public_key.public_bytes(
        encoding = serialization.Encoding.Raw,
        format = serialization.PublicFormat.Raw
    )
    print(public_bytes)
    loaded_public_key = x25519.X25519PublicKey.from_public_bytes(public_bytes)
    print(loaded_public_key)

def main():
    ed25519_signing()
    ed25519_generate_key()
    x25519_exchange()
    x25519_generate_private()
    x255219_generate_public()

if __name__ == "__main__":
    # execute only if run as a script
    main()