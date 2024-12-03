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

    def encrypt(self, plaintext, associated_data=None):
        """Encrypt a message using AES-GCM mode."""
        if not self.shared_key:
            raise ValueError("Shared key is not set.")

        # Generate a random IV (nonce)
        iv = os.urandom(12)
        cipher = AES.new(self.shared_key, AES.MODE_GCM, nonce=iv)

        # Add associated data if provided
        if associated_data:
            cipher.update(associated_data.encode("utf-8"))

        # Encrypt plaintext
        ciphertext, tag = cipher.encrypt_and_digest(plaintext.encode("utf-8"))

        # Encode IV, ciphertext, and tag in Base64 for transmission
        return (
            base64.b64encode(iv).decode("utf-8"),
            base64.b64encode(ciphertext).decode("utf-8"),
            base64.b64encode(tag).decode("utf-8")
        )

    def decrypt(self, iv_b64, ciphertext_b64, tag_b64, associated_data=None):
        """Decrypt a message using AES-GCM mode."""
        try:
            # Decode Base64 inputs
            iv = base64.b64decode(iv_b64)
            ciphertext = base64.b64decode(ciphertext_b64)
            tag = base64.b64decode(tag_b64)

            print(f"Decrypting: iv={iv_b64}, ciphertext={ciphertext_b64}, tag={tag_b64}")  # Add logging

            cipher = AES.new(self.shared_key, AES.MODE_GCM, nonce=iv)

            # Add associated data if provided
            if associated_data:
                cipher.update(associated_data.encode("utf-8"))

            # Decrypt and verify integrity
            plaintext = cipher.decrypt_and_verify(ciphertext, tag)
            return plaintext.decode("utf-8")
        except ValueError as e:
            print(f"Decryption failed: {e}")
            return None
        except Exception as e:
            print(f"Unexpected error during decryption: {e}")
            return None