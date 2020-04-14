import base64
import os
from datetime import datetime, date, time, timedelta

# This class provides both encryption and decryption facilities.
from cryptography.fernet import Fernet, MultiFernet

from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.x509 import ocsp
from cryptography.hazmat.primitives.hashes import SHA1
from cryptography.x509 import load_pem_x509_certificate, ocsp



'''
https://cryptography.io/en/latest/x509/tutorial/

X.509 certificates are used to authenticate clients and servers. The most common use case is for web servers 
using HTTPS.

Creating a Certificate Signing Request (CSR)

When obtaining a certificate from a certificate authority (CA), the usual flow is:

You generate a private/public key pair.
You create a request for a certificate, which is signed by your key (to prove that you own that key).
You give your CSR to a CA (but not the private key).
The CA validates that you own the resource (e.g. domain) you want a certificate for.
The CA gives you a certificate, signed by them, which identifies your public key, and the resource you are 
authenticated for.
You configure your server to use that certificate, combined with your private key, to server traffic.
If you want to obtain a certificate from a typical commercial CA, here’s how. First, you’ll need to generate a 
private key, we’ll generate an RSA key (these are the most common types of keys on the web right now):
'''

def generate_privateKey():
    # X509
    key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    print(key)

    # Write our key to disk for safe keeping
    with open("/Users/david/Documents/PycharmProjects/crypto/509key.pem", "wb") as f:
        f.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.BestAvailableEncryption(b"passphrase"),
        ))


def generate_CSR():
    # Generate a CSR
    csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
        # Provide various details about who we are.
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"US"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"California"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, u"San Francisco"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"My Company"),
        x509.NameAttribute(NameOID.COMMON_NAME, u"mysite.com"),
    ])).add_extension(
        x509.SubjectAlternativeName([
            # Describe what sites we want this certificate for.
            x509.DNSName(u"mysite.com"),
            x509.DNSName(u"www.mysite.com"),
            x509.DNSName(u"subdomain.mysite.com"),
        ]),
        critical=False,
        # Sign the CSR with our private key.
    ).sign(key, hashes.SHA256(), default_backend())

    # Write our CSR out to disk.
    with open("/Users/david/Documents/PycharmProjects/crypto/csr.pem", "wb") as f:
        f.write(csr.public_bytes(serialization.Encoding.PEM))


def generate_selfSignedCertificate():
    # Generate our key
    key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    # Write our key to disk for safe keeping
    with open("/Users/david/Documents/PycharmProjects/crypto/key.pem", "wb") as f:
        f.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.BestAvailableEncryption(b"passphrase"),
        ))

    # Various details about who we are. For a self-signed certificate the
    # subject and issuer are always the same.
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"US"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"California"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, u"San Francisco"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"My Company"),
        x509.NameAttribute(NameOID.COMMON_NAME, u"mysite.com"),
    ])
    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.utcnow()
    ).not_valid_after(
        # Our certificate will be valid for 10 days
        datetime.utcnow() + timedelta(days=10)
    ).add_extension(
        x509.SubjectAlternativeName([x509.DNSName(u"localhost")]),
        critical=False,
        # Sign our certificate with our private key
    ).sign(key, hashes.SHA256(), default_backend())
    # Write our certificate out to disk.
    with open("/Users/david/Documents/PycharmProjects/crypto/certificate.pem", "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    return cert


def check_certificateKeyType(cert_in, ec):
    public_key = cert_in.public_key()
    if isinstance(public_key, rsa.RSAPublicKey):
        # Do something RSA specific
        print("rsa")
    elif isinstance(public_key, ec.EllipticCurvePublicKey):
        # Do something EC specific
        print("ec")
    else:
        # Remember to handle this case
        print("something else")



"""
der_ocsp_req = b""
pem_cert = b""
pem_issuer = b""

ocsp_req = ocsp.load_der_ocsp_request(der_ocsp_req)
print(ocsp_req.serial_number)

cert = load_pem_x509_certificate(pem_cert, default_backend())
issuer = load_pem_x509_certificate(pem_issuer, default_backend())
builder = ocsp.OCSPRequestBuilder()
# SHA1 is in this example because RFC 5019 mandates its use.
builder = builder.add_certificate(cert, issuer, SHA1())
req = builder.build()
base64.b64encode(req.public_bytes(serialization.Encoding.DER))
"""

"""
pem_cert = ""
pem_issuer = ""
pem_responder_cert = ""
pem_responder_key = ""

cert = load_pem_x509_certificate(pem_cert, default_backend())
issuer = load_pem_x509_certificate(pem_issuer, default_backend())
responder_cert = load_pem_x509_certificate(pem_responder_cert, default_backend())
responder_key = serialization.load_pem_private_key(pem_responder_key, None, default_backend())
builder = ocsp.OCSPResponseBuilder()
# SHA1 is in this example because RFC 5019 mandates its use.
builder = builder.add_response(
    cert=cert, issuer=issuer, algorithm=hashes.SHA1(),
    cert_status=ocsp.OCSPCertStatus.GOOD,
    this_update=datetime.datetime.now(),
    next_update=datetime.datetime.now(),
    revocation_time=None, revocation_reason=None
).responder_id(
    ocsp.OCSPResponderEncoding.HASH, responder_cert
)
response = builder.sign(responder_key, hashes.SHA256())
response.certificate_status
"""

crl = x509.load_pem_x509_crl(pem_crl_data, default_backend())
isinstance(crl.signature_hash_algorithm, hashes.SHA256)
