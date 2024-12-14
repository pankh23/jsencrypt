import json
from encryption import encrypt_data, decrypt_data
from key_management import generate_key, save_key, load_key

# Load configuration
with open("config.json", "r") as config_file:
    config = json.load(config_file)

# Generate and save a key if not already present
try:
    key = load_key(config["key_file"])
    print("Key loaded successfully.")
except FileNotFoundError:
    print("Key not found. Generating a new key...")
    key = generate_key()
    save_key(key, config["key_file"])
    print(f"New key saved to {config['key_file']}.")

# Simulate data transmission
plaintext = b"Hello, secure world!"
print(f"\nOriginal Data: {plaintext}")

# Encrypt the data
encrypted_data = encrypt_data(plaintext, key)
print(f"Encrypted Data: {encrypted_data}")

# Decrypt the data
decrypted_data = decrypt_data(encrypted_data, key)
print(f"Decrypted Data: {decrypted_data}")
