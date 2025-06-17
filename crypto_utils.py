from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import base64
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def generate_rsa_keys():
    """Generate RSA 2048-bit key pair"""
    try:
        key = RSA.generate(2048)
        return {
            'private': key.export_key().decode(),
            'public': key.publickey().export_key().decode()
        }
    except Exception as e:
        logger.error(f"Key generation failed: {str(e)}")
        raise

def encrypt_message(public_key_pem, plaintext):
    """Encrypt message using RSA-OAEP"""
    if not public_key_pem or not plaintext:
        return None
    
    try:
        public_key = RSA.import_key(public_key_pem)
        cipher = PKCS1_OAEP.new(public_key)
        encrypted = cipher.encrypt(plaintext.encode())
        return base64.b64encode(encrypted).decode()
    except Exception as e:
        logger.error(f"Encryption failed: {str(e)}")
        return None

def decrypt_message(private_key_pem, ciphertext):
    """Decrypt message using RSA-OAEP"""
    if not private_key_pem or not ciphertext:
        return "[INVALID INPUT]"
    
    try:
        private_key = RSA.import_key(private_key_pem)
        cipher = PKCS1_OAEP.new(private_key)
        decrypted = cipher.decrypt(base64.b64decode(ciphertext))
        return decrypted.decode()
    except Exception as e:
        logger.error(f"Decryption failed: {str(e)}")
        return "[DECRYPTION FAILED]"