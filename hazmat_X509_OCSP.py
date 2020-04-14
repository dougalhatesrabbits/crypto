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
https://cryptography.io/en/latest/x509/ocsp/

OCSP

OCSP (Online Certificate Status Protocol) is a method of checking the revocation status of certificates. 
It is specified in RFC 6960, as well as other obsoleted RFCs.
'''

def load_ocsp():
    der_ocsp_req = b""
    pem_cert = b""
    pem_issuer = b""

    ocsp_req = ocsp.load_der_ocsp_request(der_ocsp_req)
    print(ocsp_req.serial_number)


def create_ocspRequest():
    cert = load_pem_x509_certificate(pem_cert, default_backend())
    issuer = load_pem_x509_certificate(pem_issuer, default_backend())
    builder = ocsp.OCSPRequestBuilder()
    # SHA1 is in this example because RFC 5019 mandates its use.
    builder = builder.add_certificate(cert, issuer, SHA1())
    req = builder.build()
    base64.b64encode(req.public_bytes(serialization.Encoding.DER))


def load_ocspResponse():
    ocsp_resp = ocsp.load_der_ocsp_response(der_ocsp_resp_unauth)
    print(ocsp_resp.response_status)
    OCSPResponseStatus.UNAUTHORIZED


def create_ocspResponse_good():
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
    return response


def _create_ocspResponseBad():
    response = ocsp.OCSPResponseBuilder.build_unsuccessful(
        ocsp.OCSPResponseStatus.UNAUTHORIZED
        )
    response.response_status



crl = x509.load_pem_x509_crl(pem_crl_data, default_backend())
isinstance(crl.signature_hash_algorithm, hashes.SHA256)
