import socket
from encryption import decrypt_data
from key_management import load_key

# Load the key
key = load_key()

# Start a TCP server
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind(("0.0.0.0", 12345))  # Listen on all network interfaces (0.0.0.0) and port 12345
server_socket.listen(1)
print("Server listening on port 12345...")

while True:
    client_socket, addr = server_socket.accept()
    print(f"Connection established with {addr}")
    
    encrypted_data = client_socket.recv(1024)  # Receive data from client (max 1024 bytes)
    decrypted_data = decrypt_data(encrypted_data, key)
    print(f"Received Data (Decrypted): {decrypted_data}")
    
    client_socket.close()  # Close the connection with the client.