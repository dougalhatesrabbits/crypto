from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

'''
RSA

RSA is a public-key algorithm for encrypting and signing messages.

Generation

Unlike symmetric cryptography, where the key is typically just a random series of bytes, RSA keys have a complex
internal structure with specific mathematical properties.
'''

def rsa_generate_key():
    """
    Generates a new RSA private key using the provided backend. key_size describes how many bits long the key should be.
    Larger keys provide more security; currently 1024 and below are considered breakable while 2048 or 4096 are
    reasonable default key sizes for new keys. The public_exponent indicates what one mathematical property of the key
    generation will be. Unless you have a specific reason to do otherwise, you should always use 65537.
    :return:
    """
    private_key = rsa.generate_private_key(
        public_exponent = 65537,
        key_size = 2048,
        backend = default_backend()
    )
    print(private_key)

def rsa_load_key():
    """
    If you already have an on-disk key in the PEM format (which are recognizable by the distinctive
    -----BEGIN {format}----- and -----END {format}----- markers), you can load it:
    :return:
    """
    with open("/Users/david/Documents/PycharmProjects/crypto/509key.pem", "rb") as key_file:
        private_key = serialization.load_pem_private_key(
        key_file.read(),
        password = b'passphrase',
        backend = default_backend()
    )
    print(private_key)


def main():
    rsa_generate_key()
    rsa_load_key()


if __name__ == "__main__":
    # execute only if run as a script
    main()