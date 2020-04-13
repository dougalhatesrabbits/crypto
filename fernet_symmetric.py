import base64
import os
from datetime import datetime, date, time, timedelta

# This class provides both encryption and decryption facilities.
from cryptography.fernet import Fernet, MultiFernet

from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes



'''
https://cryptography.io/en/latest/fernet/
Fernet (symmetric encryption)
'''

def generate_key():
    # Generates a fresh fernet key. Keep this some place safe! If you lose it you’ll no longer be able to decrypt messages;
    # if anyone else gains access to it, they’ll be able to decrypt all of your messages, and they’ll also be able forge
    # arbitrary messages that will be authenticated and decrypted.
    key = Fernet.generate_key()
    f = Fernet(key)

    # Encrypts data passed. The result of this encryption is known as a “Fernet token” and has strong privacy
    # and authenticity guarantees.
    token = f.encrypt(b"my deep dark secret")
    print(token)
    return token


def decrypt_key(token_in):
    # Decrypts a Fernet token. If successfully decrypted you will receive the original plaintext as the result,
    # otherwise an exception will be raised. It is safe to use this data immediately as Fernet verifies that the data
    # has not been tampered with prior to returning it.
    plaintext = f.decrypt(token_in)
    print(plaintext)

def key_rotation():
    # -----------------------------
    key1 = Fernet(Fernet.generate_key())
    print(key1)
    key2 = Fernet(Fernet.generate_key())
    print(key2)
    f = MultiFernet([key1, key2])
    token = f.encrypt(b"Secret message!")
    print(token)
    return key1, key2

    plaintext = f.decrypt(token)
    print(plaintext)

def key_rotation_new(key1_in, key2_in):
    key3 = Fernet(Fernet.generate_key())
    print(key3)
    f2 = MultiFernet([key3, key1_in, key2_in])
    rotated = f2.rotate(token)
    plaintext = f2.decrypt(rotated)
    print(plaintext)


def password():
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


