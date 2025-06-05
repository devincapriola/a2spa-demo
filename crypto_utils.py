from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
import os

KEY_DIR = "keys"
os.makedirs(KEY_DIR, exist_ok=True)

def generate_keys(agent_name):
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()

    with open(f"{KEY_DIR}/{agent_name}_private.pem", "wb") as f:
        f.write(private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption()
        ))

    with open(f"{KEY_DIR}/{agent_name}_public.pem", "wb") as f:
        f.write(public_key.public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo
        ))

def load_keys(agent_name):
    with open(f"{KEY_DIR}/{agent_name}_private.pem", "rb") as f:
        private_key = serialization.load_pem_private_key(f.read(), password=None)
    with open(f"{KEY_DIR}/{agent_name}_public.pem", "rb") as f:
        public_key = serialization.load_pem_public_key(f.read())
    return private_key, public_key

def sign_payload(private_key, payload: bytes):
    return private_key.sign(payload, padding.PKCS1v15(), hashes.SHA256())

def verify_signature(public_key, payload: bytes, signature: bytes):
    try:
        public_key.verify(signature, payload, padding.PKCS1v15(), hashes.SHA256())
        return True
    except Exception:
        return False
