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

'''
Generates a fresh fernet key. Keep this some place safe! If you lose it you’ll no longer be able to decrypt messages; 
if anyone else gains access to it, they’ll be able to decrypt all of your messages, and they’ll also be able forge 
arbitrary messages that will be authenticated and decrypted.
'''
key = Fernet.generate_key()
f = Fernet(key)
token = f.encrypt(b"my deep dark secret")
token
b'...'
f.decrypt(token)
b'my deep dark secret'

# -----------------------------
key1 = Fernet(Fernet.generate_key())
key2 = Fernet(Fernet.generate_key())
f = MultiFernet([key1, key2])
token = f.encrypt(b"Secret message!")
token
b'...'
f.decrypt(token)
b'Secret message!'

key3 = Fernet(Fernet.generate_key())
f2 = MultiFernet([key3, key1, key2])
rotated = f2.rotate(token)
f2.decrypt(rotated)
b'Secret message!'

password = b"password"
salt = os.urandom(16)
kdf = PBKDF2HMAC(
    algorithm=hashes.SHA256(),
    length=32,
    salt=salt,
    iterations=100000,
    backend=default_backend()
)
key = base64.urlsafe_b64encode(kdf.derive(password))
f = Fernet(key)
token = f.encrypt(b"Secret message!")
token
b'...'
f.decrypt(token)
b'Secret message!'

# X509
key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend()
)
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
