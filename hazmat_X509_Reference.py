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
https://cryptography.io/en/latest/x509/reference/
'''

def load_certificate():
    cert = x509.load_pem_x509_certificate(pem_data, default_backend())
    print(cert.serial_number)

def load_crl():
    crl = x509.load_pem_x509_crl(pem_crl_data, default_backend())
    isinstance(crl.signature_hash_algorithm, hashes.SHA256)
