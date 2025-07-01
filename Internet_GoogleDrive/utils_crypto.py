from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5, DES3, AES
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA512
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import base64

def load_key(path):
    with open(path, 'rb') as f:
        return RSA.import_key(f.read())

def generate_session_key():
    return get_random_bytes(24)  # Độ dài 192-bit cho DES3

def encrypt_session_key(session_key, pub_key):
    cipher = PKCS1_v1_5.new(pub_key)
    return cipher.encrypt(session_key)

def decrypt_session_key(enc_key, priv_key):
    cipher = PKCS1_v1_5.new(priv_key)
    return cipher.decrypt(enc_key, None)

def encrypt_3des(data, key, iv):
    cipher = DES3.new(key, DES3.MODE_CBC, iv)
    padded_data = pad(data, DES3.block_size)
    return cipher.encrypt(padded_data)

def decrypt_3des(data, key, iv):
    cipher = DES3.new(key, DES3.MODE_CBC, iv)
    padded_data = cipher.decrypt(data)
    return unpad(padded_data, DES3.block_size)

def sign_data(data, priv_key):
    h = SHA512.new(data)
    signer = pkcs1_15.new(priv_key)
    try:
        return signer.sign(h)
    except ValueError as e:
        raise ValueError(f"Lỗi ký dữ liệu: Khóa không hợp lệ hoặc dữ liệu không ký được - {e}")
    except Exception as e:
        raise ValueError(f"Lỗi ký dữ liệu không xác định: {e}")

def verify_signature(data, sig, pub_key):
    h = SHA512.new(data)
    verifier = pkcs1_15.new(pub_key)
    try:
        verifier.verify(h, sig)
        return True
    except (ValueError, TypeError):
        return False

def aes_encrypt(data, key, iv):
    if len(key) not in (16, 24, 32):
        raise ValueError("Độ dài khóa AES phải là 16, 24 hoặc 32 byte!")
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_data = pad(data, AES.block_size)
    return cipher.encrypt(padded_data)

def aes_decrypt(data, key, iv):
    if len(key) not in (16, 24, 32):
        raise ValueError("Độ dài khóa AES phải là 16, 24 hoặc 32 byte!")
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_data = cipher.decrypt(data)
    return unpad(padded_data, AES.block_size)