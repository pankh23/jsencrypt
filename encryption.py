# from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
# import os

# # Encrypt data
# def encrypt_data(plaintext, key):
#     iv = os.urandom(16)  # Initialization Vector
#     cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
#     encryptor = cipher.encryptor()
    
#     # Padding plaintext to make it a multiple of 16 bytes
#     padding = 16 - len(plaintext) % 16
#     plaintext += bytes([padding] * padding)
    
#     ciphertext = encryptor.update(plaintext) + encryptor.finalize()
#     return iv + ciphertext  # Return IV prepended to ciphertext

# # Decrypt data
# def decrypt_data(ciphertext, key):
#     iv = ciphertext[:16]  # Extract IV
#     encrypted_data = ciphertext[16:]
#     cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
#     decryptor = cipher.decryptor()
#     plaintext_padded = decryptor.update(encrypted_data) + decryptor.finalize()
    
#     # Remove padding
#     padding = plaintext_padded[-1]
#     plaintext = plaintext_padded[:-padding]
#     return plaintext
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
import os

# Generate a random AES key (16 bytes for AES-128, 32 bytes for AES-256)
def generate_key(key_size=32):
    return os.urandom(key_size)

# Encrypt data
def encrypt_data(plaintext, key):
    """
    Encrypts the plaintext using AES encryption in CBC mode.

    Args:
        plaintext (bytes): The plaintext data to encrypt.
        key (bytes): The encryption key (16, 24, or 32 bytes).

    Returns:
        bytes: The IV concatenated with the encrypted ciphertext.
    """
    iv = os.urandom(16)  # Initialization Vector
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()

    # Apply padding to make the plaintext a multiple of the block size
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_plaintext = padder.update(plaintext) + padder.finalize()

    ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()
    return iv + ciphertext  # Return IV prepended to ciphertext

# Decrypt data
def decrypt_data(ciphertext, key):
    """
    Decrypts the ciphertext using AES decryption in CBC mode.

    Args:
        ciphertext (bytes): The IV concatenated with the encrypted ciphertext.
        key (bytes): The decryption key (16, 24, or 32 bytes).

    Returns:
        bytes: The original plaintext after decryption.
    """
    iv = ciphertext[:16]  # Extract IV
    encrypted_data = ciphertext[16:]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    decryptor = cipher.decryptor()

    # Decrypt the data
    padded_plaintext = decryptor.update(encrypted_data) + decryptor.finalize()

    # Remove padding to get the original plaintext
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
    return plaintext

# Example Usage
if __name__ == "__main__":
    key = generate_key()  # Generate a 256-bit AES key
    original_text = b"Secure message for AES encryption!"
    print("Original:", original_text)

    encrypted = encrypt_data(original_text, key)
    print("Encrypted:", encrypted)

    decrypted = decrypt_data(encrypted, key)
    print("Decrypted:", decrypted)
