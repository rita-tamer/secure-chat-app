from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import base64
import os


class EncryptionUtils:
    def __init__(self):
        self.shared_key = None
        self.private_key = None
        self.public_key = None
        self.prime = 23  # Replace with a large safe prime for production
        self.base = 5    # Replace with a generator for production

    def generate_key_pair(self):
        """Generate Diffie-Hellman private and public keys."""
        self.private_key = int.from_bytes(os.urandom(16), "big")  # Random private key
        self.public_key = pow(self.base, self.private_key, self.prime)  # Public key calculation

    def compute_shared_key(self, other_public_key):
        """Compute the shared AES key using the received public key."""
        if not self.private_key:
            raise ValueError("Private key is not set.")
        shared_secret = pow(other_public_key, self.private_key, self.prime)  # DH shared secret
        self.shared_key = shared_secret.to_bytes(16, "big")[:16]  # Derive 16-byte AES key

    def encrypt(self, plaintext):
        """Encrypt a message using AES."""
        if not self.shared_key:
            raise ValueError("Shared key is not set.")
        cipher = AES.new(self.shared_key, AES.MODE_CBC)
        iv = cipher.iv
        ciphertext = cipher.encrypt(pad(plaintext.encode("utf-8"), AES.block_size))
        return base64.b64encode(iv).decode("utf-8") + ":" + base64.b64encode(ciphertext).decode("utf-8")

    def decrypt(self, encrypted_message):
        """Decrypt a message using AES."""
        if not self.shared_key:
            raise ValueError("Shared key is not set.")
        try:
            iv_b64, ct_b64 = encrypted_message.split(":")
            iv = base64.b64decode(iv_b64)
            ciphertext = base64.b64decode(ct_b64)
            cipher = AES.new(self.shared_key, AES.MODE_CBC, iv)
            plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
            return plaintext.decode("utf-8")
        except Exception as e:
            print(f"Decryption failed: {e}")
            return None
