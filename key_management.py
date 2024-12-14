# import os

# # Generate a secure AES key
# def generate_key():
#     return os.urandom(32)  # 256-bit key

# # Save the key to a file
# def save_key(key, filename="key.key"):
#     with open(filename, "wb") as key_file:
#         key_file.write(key)

# # Load the key from a file
# def load_key(filename="key.key"):
#     with open(filename, "rb") as key_file:
#         return key_file.read()


import os

# Generate a secure AES key
def generate_key(key_size=32):
    """
    Generates a secure AES key.
    
    Args:
        key_size (int): The size of the key in bytes (16 for AES-128, 24 for AES-192, 32 for AES-256).
        
    Returns:
        bytes: A securely generated random key.
    """
    if key_size not in [16, 24, 32]:
        raise ValueError("Key size must be 16, 24, or 32 bytes.")
    return os.urandom(key_size)

# Save the key to a file
def save_key(key, filename="key.key"):
    """
    Saves the AES key to a file.
    
    Args:
        key (bytes): The AES key to save.
        filename (str): The file name where the key will be saved.
    """
    try:
        with open(filename, "wb") as key_file:
            key_file.write(key)
        print(f"Key saved to {filename}")
    except Exception as e:
        print(f"Error saving key: {e}")

# Load the key from a file
def load_key(filename="key.key"):
    """
    Loads the AES key from a file.
    
    Args:
        filename (str): The file name from which the key will be loaded.
        
    Returns:
        bytes: The loaded AES key.
    """
    try:
        if not os.path.exists(filename):
            raise FileNotFoundError(f"Key file {filename} not found. Please generate and save a key first.")
        with open(filename, "rb") as key_file:
            key = key_file.read()
        print(f"Key loaded from {filename}")
        return key
    except Exception as e:
        print(f"Error loading key: {e}")
        return None

# Example Usage
if __name__ == "__main__":
    key_file = "key.key"

    # Check if a key file exists; if not, generate a new key
    if not os.path.exists(key_file):
        print("No key file found. Generating a new key...")
        aes_key = generate_key()  # Default is 256-bit key
        save_key(aes_key, key_file)
    else:
        print("Key file found. Loading key...")
        aes_key = load_key(key_file)

    if aes_key:
        print(f"Loaded Key (Base64): {aes_key.hex()}")

