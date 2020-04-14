import base64
import os
from datetime import datetime, date, time, timedelta

from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
#import datetime



'''
https://cryptography.io/en/latest/x509/reference/
'''

def load_certificate(pem_data):
    cert = x509.load_pem_x509_certificate(pem_data, default_backend())
    print(cert.serial_number)


def load_crl(pem_crl_data):
    crl = x509.load_pem_x509_crl(pem_crl_data, default_backend())
    isinstance(crl.signature_hash_algorithm, hashes.SHA256)


def load_csr(pem_req_data):
    csr = x509.load_pem_x509_csr(pem_req_data, default_backend())
    isinstance(csr.signature_hash_algorithm, hashes.SHA1)


def get_certificateObjects(cert):
    print(cert.version)
    print(cert.fingerprint(hashes.SHA256()))
    print(cert.serial_number)
    public_key = cert.public_key()
    print(isinstance(public_key, rsa.RSAPublicKey))
    print(cert.not_valid_before)
    print(cert.not_valid_after)
    print(isinstance(cert.signature_hash_algorithm, hashes.SHA256))
    print(cert.signature_algorithm_oid)
    for ext in cert.extensions:
        print(ext)



def check_RSAPublicKeys(pem_issuer_public_key,pem_data_to_check):
    """
    The DER encoded bytes payload (as defined by RFC 5280) that is hashed and then signed by the private key of the 
    certificate’s issuer. This data may be used to validate a signature, but use extreme caution as certificate 
    validation is a complex problem that involves much more than just signature checks.

    To validate the signature on a certificate you can do the following. Note: This only verifies that the certificate 
    was signed with the private key associated with the public key provided and does not perform any of the other checks 
    needed for secure certificate validation. Additionally, this example will only work for RSA public keys with 
    PKCS1v15 signatures, and so it can’t be used for general purpose signature verification.
    """
    issuer_public_key = load_pem_public_key(pem_issuer_public_key, default_backend())
    cert_to_check = x509.load_pem_x509_certificate(pem_data_to_check, default_backend())
    issuer_public_key.verify(
    cert_to_check.signature,
    cert_to_check.tbs_certificate_bytes,
    # Depends on the algorithm used to create the certificate
    padding.PKCS1v15(),
    cert_to_check.signature_hash_algorithm,
    )


"""
X.509 CRL (Certificate Revocation List) Object
"""
def get_crlObjects(crl):
    print(len(crl))
    revoked_certificate = crl[0]
    print(type(revoked_certificate))
    for r in crl:
        print(r.serial_number)
    print(crl.fingerprint(hashes.SHA256()))
    print(isinstance(crl.signature_hash_algorithm, hashes.SHA256))
    print(crl.signature_algorithm_oid)
    print(crl.issuer)
    print(crl.next_update)
    print(crl.last_update)


"""
X.509 Certificate Builder
"""


def create_certificate():
    one_day = datetime.timedelta(1, 0, 0)
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )

    public_key = private_key.public_key()
    builder = x509.CertificateBuilder()
    builder = builder.subject_name(x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, u'cryptography.io'),
    ]))
    builder = builder.issuer_name(x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, u'cryptography.io'),
    ]))
    builder = builder.not_valid_before(datetime.datetime.today() - one_day)
    builder = builder.not_valid_after(datetime.datetime.today() + (one_day * 30))
    builder = builder.serial_number(x509.random_serial_number())
    builder = builder.public_key(public_key)
    builder = builder.add_extension(

        x509.SubjectAlternativeName(
            [x509.DNSName(u'cryptography.io')]
        ),

        critical=False
    )
    builder = builder.add_extension(

        x509.BasicConstraints(ca=False, path_length=None), critical=True,
    )
    certificate = builder.sign(

        private_key=private_key, algorithm=hashes.SHA256(),

        backend=default_backend()
    )
    print(isinstance(certificate, x509.Certificate))
