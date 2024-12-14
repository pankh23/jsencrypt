# import socket
# from encryption import encrypt_data
# from key_management import load_key

# # Load the key
# key = load_key()

# # Start a TCP client
# client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
# client_socket.connect(("192.168.216.148:5000", 12345))

# data_to_send = b"Hello, secure server!"  # Data to send
# encrypted_data = encrypt_data(data_to_send, key)  # Encrypt the data
# client_socket.send(encrypted_data)  # Send encrypted data to the server
# print("Encrypted data sent.")

# client_socket.close()  # Close the connection after sending the data
# from flask import Flask, render_template, request
# from Crypto.Cipher import AES
# from Crypto.Util.Padding import pad, unpad
# from cryptography.hazmat.primitives.asymmetric import rsa, padding
# from cryptography.hazmat.primitives import hashes, serialization
# import base64

# app = Flask(__name__)

# # Load RSA keys
# with open("private.pem", "rb") as key_file:
#     private_key = serialization.load_pem_private_key(
#         key_file.read(),
#         password=None
#     )

# with open("public.pem", "rb") as key_file:
#     public_key = key_file.read()

# # AES Configuration
# AES_KEY = b'securekeysecurek'  # 16 bytes key
# AES_IV = b'1234567890123456'   # 16 bytes IV

# def aes_decrypt(encrypted_message):
#     cipher = AES.new(AES_KEY, AES.MODE_CBC, AES_IV)
#     decrypted_data = unpad(cipher.decrypt(base64.b64decode(encrypted_message)), AES.block_size)
#     return decrypted_data.decode('utf-8')

# @app.route('/')
# def home():
#     return render_template('index.html', title="Secure Messaging Home", heading="Welcome to Secure Messaging System")

# @app.route('/encrypt', methods=['POST'])
# def encrypt():
#     algorithm = request.form['algorithm']
#     encrypted_message = request.form['encrypted_message']
    
#     if algorithm == 'aes':
#         decrypted_message = aes_decrypt(encrypted_message)
#     elif algorithm == 'rsa':
#         decrypted_message = private_key.decrypt(
#             base64.b64decode(encrypted_message),
#             padding.OAEP(
#                 mgf=padding.MGF1(algorithm=hashes.SHA256()),
#                 algorithm=hashes.SHA256(),
#                 label=None
#             )
#         ).decode('utf-8')
#     elif algorithm == 'reverse':
#         decrypted_message = encrypted_message[::-1]
#     else:
#         decrypted_message = "Unsupported algorithm."

#     return f"Decrypted message: {decrypted_message}"

# if __name__ == "__main__":
#     app.run(host="0.0.0.0", port=5000, debug=True)
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Util.Padding import pad
import base64

# Load the public key (assumed to be in 'public.pem')
with open('public.pem', 'rb') as f:
    public_key = RSA.import_key(f.read())

cipher = PKCS1_OAEP.new(public_key)
message = "Hello, this is a secret message."
encrypted_message = cipher.encrypt(message.encode())

# Encode the encrypted message in base64
encrypted_message_base64 = base64.b64encode(encrypted_message).decode('utf-8')
print("Encrypted Message (Base64):", encrypted_message_base64)