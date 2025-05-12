from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes

def load_rsa_key(path=None, data=None):
    if data:
        return RSA.import_key(data)
    if path:
        with open(path, "rb") as f:
            return RSA.import_key(f.read())
    raise ValueError("Provide path or data for RSA key")

def rsa_encrypt(data: bytes, pubkey_path=None, pubkey_data=None) -> bytes:
    key = load_rsa_key(path=pubkey_path, data=pubkey_data)
    cipher = PKCS1_OAEP.new(key)
    return cipher.encrypt(data)

def rsa_decrypt(ciphertext: bytes, privkey_path=None, privkey_data=None) -> bytes:
    key = load_rsa_key(path=privkey_path, data=privkey_data)
    cipher = PKCS1_OAEP.new(key)
    return cipher.decrypt(ciphertext)

def aes_encrypt(plaintext: bytes, key: bytes) -> bytes:
    iv = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    return iv + tag + ciphertext

def aes_decrypt(ciphertext: bytes, key: bytes) -> bytes:
    iv, tag, ct = ciphertext[:16], ciphertext[16:32], ciphertext[32:]
    cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
    return cipher.decrypt_and_verify(ct, tag)
