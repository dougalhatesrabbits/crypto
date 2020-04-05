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
https://cryptography.io/en/latest/fernet/
Fernet (symmetric encryption)
'''
# Generates a fresh fernet key. Keep this some place safe! If you lose it you’ll no longer be able to decrypt messages;
# if anyone else gains access to it, they’ll be able to decrypt all of your messages, and they’ll also be able forge
# arbitrary messages that will be authenticated and decrypted.
key = Fernet.generate_key()
f = Fernet(key)

# Encrypts data passed. The result of this encryption is known as a “Fernet token” and has strong privacy
# and authenticity guarantees.
token = f.encrypt(b"my deep dark secret")
print(token)

# Decrypts a Fernet token. If successfully decrypted you will receive the original plaintext as the result,
# otherwise an exception will be raised. It is safe to use this data immediately as Fernet verifies that the data
# has not been tampered with prior to returning it.
plaintext = f.decrypt(token)
print(plaintext)

# -----------------------------
key1 = Fernet(Fernet.generate_key())
print(key1)
key2 = Fernet(Fernet.generate_key())
print(key2)
f = MultiFernet([key1, key2])
token = f.encrypt(b"Secret message!")
print(token)

plaintext = f.decrypt(token)
print(plaintext)

key3 = Fernet(Fernet.generate_key())
print(key3)
f2 = MultiFernet([key3, key1, key2])
rotated = f2.rotate(token)
plaintext = f2.decrypt(rotated)
print(plaintext)

password = b"password"
salt = os.urandom(16)
kdf = PBKDF2HMAC(
    algorithm=hashes.SHA256(),
    length=32,
    salt=salt,
    iterations=1000000,
    backend=default_backend()
)
key = base64.urlsafe_b64encode(kdf.derive(password))
f = Fernet(key)
token = f.encrypt(b"Secret message!")
print(token)

plaintext = f.decrypt(token)
print(plaintext)


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

public_key = cert.public_key()
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
