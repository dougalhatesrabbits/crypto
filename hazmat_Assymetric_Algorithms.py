from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.asymmetric.ed448 import Ed448PrivateKey
from cryptography.hazmat.primitives.asymmetric.x448 import X448PrivateKey
from cryptography.hazmat.primitives.asymmetric import x448
from cryptography.hazmat.primitives.asymmetric import ec

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


def ed448_signing():
    """
    Ed448 signing

    Ed448 is an elliptic curve signing algorithm using EdDSA.
    :return:
    """
    private_key = Ed448PrivateKey.generate()
    print(private_key)
    signature = private_key.sign(b"my authenticated message")
    print(signature)
    public_key = private_key.public_key()
    print(public_key)
    # Raises InvalidSignature if verification fails
    print(public_key.verify(signature, b"my authenticated message"))


def ed448_exchange():
    """
    X448 key exchange

    X448 is an elliptic curve Diffie-Hellman key exchange using Curve448. It allows two parties to jointly agree on a
    shared secret using an insecure channel.

    Exchange Algorithm

    For most applications the shared_key should be passed to a key derivation function. This allows mixing of additional
    information into the key, derivation of multiple keys, and destroys any structure that may be present.

    :return:
    """
    # Generate a private key for use in the exchange.
    private_key = X448PrivateKey.generate()
    print(private_key)
    # In a real handshake the peer_public_key will be received from the
    # other party. For this example we'll generate another private key and
    # get a public key from that. Note that in a DH handshake both peers
    # must agree on a common set of parameters.
    peer_public_key = X448PrivateKey.generate().public_key()
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
    private_key_2 = X448PrivateKey.generate()
    print(private_key_2)
    peer_public_key_2 = X448PrivateKey.generate().public_key()
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


def ed448_generate_private():
    """
    Generate an X448 private key.
    :return:
    """
    private_key = x448.X448PrivateKey.generate()
    print(private_key)
    private_bytes = private_key.private_bytes(
        encoding = serialization.Encoding.Raw,
        format = serialization.PrivateFormat.Raw,
        encryption_algorithm = serialization.NoEncryption()
    )
    print(private_bytes)
    loaded_private_key = x448.X448PrivateKey.from_private_bytes(private_bytes)
    print(loaded_private_key)


def ed448_generate_public():
    private_key = x448.X448PrivateKey.generate()
    print(private_key)
    public_key = private_key.public_key()
    print(public_key)
    public_bytes = public_key.public_bytes(
        encoding = serialization.Encoding.Raw,
        format = serialization.PublicFormat.Raw
    )
    print(public_bytes)
    loaded_public_key = x448.X448PublicKey.from_public_bytes(public_bytes)
    print(loaded_public_key)


def ecdsa_signing():
    """
    The ECDSA signature algorithm first standardized in NIST publication FIPS 186-3, and later in FIPS 186-4.
    :return:
    """
    private_key = ec.generate_private_key(
        ec.SECP384R1(), default_backend()
    )
    print(private_key)
    data = b"this is some data I'd like to sign"
    print(data)
    signature = private_key.sign(
        data,
        ec.ECDSA(hashes.SHA256())
    )
    print(signature)


def ecdh_exchange():
    """
    The Elliptic Curve Diffie-Hellman Key Exchange algorithm first standardized in NIST publication 800-56A, and later
    in 800-56Ar2.

    For most applications the shared_key should be passed to a key derivation function. This allows mixing of additional
    information into the key, derivation of multiple keys, and destroys any structure that may be present.

    *******
    Warning
    *******
    This example does not give forward secrecy and is only provided as a demonstration of the basic Diffie-Hellman
    construction. For real world applications always use the ephemeral form described after this example.
    :return:
    """
    # Generate a private key for use in the exchange.
    server_private_key = ec.generate_private_key(
        ec.SECP384R1(), default_backend()
    )
    print(server_private_key)
    # In a real handshake the peer is a remote client. For this
    # example we'll generate another local private key though.
    peer_private_key = ec.generate_private_key(
        ec.SECP384R1(), default_backend()
    )
    print(peer_private_key)
    shared_key = server_private_key.exchange(
        ec.ECDH(), peer_private_key.public_key())
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
    # And now we can demonstrate that the handshake performed in the
    # opposite direction gives the same final value
    same_shared_key = peer_private_key.exchange(
        ec.ECDH(), server_private_key.public_key())
    print(same_shared_key)
    # Perform key derivation.
    same_derived_key = HKDF(
        algorithm = hashes.SHA256(),
        length = 32,
        salt = None,
        info = b'handshake data',
        backend = default_backend()
    ).derive(same_shared_key)
    print(same_derived_key)
    derived_key == same_derived_key
    print(derived_key)


def ecdhe_exchange():
    """
    ECDHE (or EECDH), the ephemeral form of this exchange, is strongly preferred over simple ECDH and provides forward
    secrecy when used. You must generate a new private key using generate_private_key() for each exchange() when
    performing an ECDHE key exchange. An example of the ephemeral form:
    :return:
    """
    # Generate a private key for use in the exchange.
    private_key = ec.generate_private_key(
        ec.SECP384R1(), default_backend()
    )
    print(private_key)
    # In a real handshake the peer_public_key will be received from the
    # other party. For this example we'll generate another private key
    # and get a public key from that.
    peer_public_key = ec.generate_private_key(
        ec.SECP384R1(), default_backend()
    ).public_key()
    print(peer_public_key)
    shared_key = private_key.exchange(ec.ECDH(), peer_public_key)
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
    private_key_2 = ec.generate_private_key(
        ec.SECP384R1(), default_backend()
    )
    print(private_key_2)
    peer_public_key_2 = ec.generate_private_key(
        ec.SECP384R1(), default_backend()
    ).public_key()
    print(peer_public_key_2)
    shared_key_2 = private_key_2.exchange(ec.ECDH(), peer_public_key_2)
    print(shared_key_2)
    derived_key_2 = HKDF(
        algorithm = hashes.SHA256(),
        length = 32,
        salt = None,
        info = b'handshake data',
        backend = default_backend()
    ).derive(shared_key_2)
    print(derived_key_2)


def ec_private_serialized():
    """
    This sample demonstrates how to generate a private key and serialize it.
    :return:
    """
    private_key = ec.generate_private_key(ec.SECP384R1(), default_backend())
    print(private_key)
    serialized_private = private_key.private_bytes(
        encoding = serialization.Encoding.PEM,
        format = serialization.PrivateFormat.PKCS8,
        encryption_algorithm = serialization.BestAvailableEncryption(b'testpassword')
    )
    print(serialized_private)
    serialized_private.splitlines()[0]

    public_key = private_key.public_key()
    serialized_public = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    print(serialized_public)
    serialized_public.splitlines()[0]

    loaded_public_key = serialization.load_pem_public_key(
    serialized_public,
    backend = default_backend()
    )

    loaded_private_key = serialization.load_pem_private_key(
    serialized_private,
        # or password=None, if in plain text
        password = b'testpassword',
        backend = default_backend()
    )


def ec_public_serialized(private_key):
    public_key = private_key.public_key()
    serialized_public = public_key.public_bytes(
        encoding = serialization.Encoding.PEM,
        format = serialization.PublicFormat.SubjectPublicKeyInfo
    )
    serialized_public.splitlines()[0]


def main():
    ed25519_signing()
    ed25519_generate_key()
    x25519_exchange()
    x25519_generate_private()
    x255219_generate_public()
    ed448_signing()
    ed448_exchange()
    ed448_generate_private()
    ed448_generate_public()
    ecdsa_signing()
    ecdh_exchange()
    ecdhe_exchange()
    ec_private_serialized()
    #ec_public_serialized()


if __name__ == "__main__":
    # execute only if run as a script
    main()