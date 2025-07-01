from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5, DES3
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA512
from Crypto.Random import get_random_bytes
import base64

def load_key(path):
    with open(path, 'rb') as f:
        return RSA.import_key(f.read())

def generate_session_key():
    return get_random_bytes(24)  # Triple DES key

def encrypt_session_key(session_key, pub_key):
    cipher = PKCS1_v1_5.new(pub_key)
    return cipher.encrypt(session_key)

def decrypt_session_key(enc_key, priv_key):
    cipher = PKCS1_v1_5.new(priv_key)
    return cipher.decrypt(enc_key, None)

def encrypt_3des(data, key, iv):
    cipher = DES3.new(key, DES3.MODE_CBC, iv)
    while len(data) % 8 != 0:
        data += b' '
    return cipher.encrypt(data)

def decrypt_3des(data, key, iv):
    cipher = DES3.new(key, DES3.MODE_CBC, iv)
    return cipher.decrypt(data).rstrip(b' ')

def sign_data(data, priv_key):
    h = SHA512.new(data)
    return pkcs1_15.new(priv_key).sign(h)

def verify_signature(data, sig, pub_key):
    h = SHA512.new(data)
    try:
        pkcs1_15.new(pub_key).verify(h, sig)
        return True
    except (ValueError, TypeError):
        return False