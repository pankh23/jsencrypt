from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os

# Encrypt data
def encrypt_data(plaintext, key):
    iv = os.urandom(16)  # Initialization Vector
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    
    # Padding plaintext to make it a multiple of 16 bytes
    padding = 16 - len(plaintext) % 16
    plaintext += bytes([padding] * padding)
    
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    return iv + ciphertext  # Return IV prepended to ciphertext

# Decrypt data
def decrypt_data(ciphertext, key):
    iv = ciphertext[:16]  # Extract IV
    encrypted_data = ciphertext[16:]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    plaintext_padded = decryptor.update(encrypted_data) + decryptor.finalize()
    
    # Remove padding
    padding = plaintext_padded[-1]
    plaintext = plaintext_padded[:-padding]
    return plaintext
