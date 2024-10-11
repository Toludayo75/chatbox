# import socket
# import threading
# from Crypto.Cipher import AES
# from Crypto.Util.Padding import pad, unpad
# import base64

# # Encryption key
# key = b'Sixteen byte key'

# # Encryption and Decryption functions
# def encrypt_message(message):
#     cipher = AES.new(key, AES.MODE_CBC)
#     ct_bytes = cipher.encrypt(pad(message.encode('utf-8'), AES.block_size))
#     iv = cipher.iv
#     ct = base64.b64encode(iv + ct_bytes).decode('utf-8')
#     return ct

# def decrypt_message(ciphertext):
#     ct = base64.b64decode(ciphertext)
#     iv = ct[:16]
#     ct = ct[16:]
#     cipher = AES.new(key, AES.MODE_CBC, iv)
#     pt = unpad(cipher.decrypt(ct), AES.block_size)
#     return pt.decode('utf-8')

# # List to hold client connections and usernames
# clients = {}  # Format: {username: client_socket}

# # Function to handle client connections
# def handle_client(client_socket, client_address):
#     # Get the username from the client
#     encrypted_username = client_socket.recv(1024).decode('utf-8')
#     username = decrypt_message(encrypted_username)
#     clients[username] = client_socket  # Store the client by username
#     print(f"{username} connected from {client_address}")

#     while True:
#         try:
#             # Receive message from the client
#             encrypted_message = client_socket.recv(1024).decode('utf-8')
#             if not encrypted_message:
#                 break  # If the message is empty, break the loop

#             # Decrypt the received message
#             message = decrypt_message(encrypted_message)
#             print(f"Received message from {username}: {message}")

#             # Check if the message is for a specific user (e.g., @username message)
#             if message.startswith("@"):
#                 # Extract the recipient's username and the actual message
#                 recipient, msg_to_send = message.split(" ", 1)
#                 recipient = recipient[1:]  # Remove the '@' symbol

#                 # If the recipient is in the clients list, send them the message
#                 if recipient in clients:
#                     encrypted_response = encrypt_message(f"{username}: {msg_to_send}")
#                     clients[recipient].send(encrypted_response.encode('utf-8'))
#                 else:
#                     # If recipient not found, notify the sender
#                     error_message = f"User {recipient} not found!"
#                     client_socket.send(encrypt_message(error_message).encode('utf-8'))
#             else:
#                 # Optionally, handle broadcast or other logic
#                 print(f"Broadcast from {username}: {message}")

#         except:
#             print(f"Connection with {username} closed.")
#             break

#     # Remove client from the list and close the connection
#     del clients[username]
#     client_socket.close()

# # Function to start the server
# def start_server():
#     server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#     server_socket.bind(('127.0.0.1', 12345))  # Use your server's IP address
#     server_socket.listen()

#     print("Server is waiting for connections...")

#     while True:
#         client_socket, client_address = server_socket.accept()
#         print(f"New connection from {client_address}")

#         # Handle the new client in a separate thread
#         client_thread = threading.Thread(target=handle_client, args=(client_socket, client_address))
#         client_thread.start()

# # Start the server
# start_server()


import socket
import threading
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import base64

# Encryption key
key = b'Sixteen byte key'

# Encryption and Decryption functions
def encrypt_message(message):
    cipher = AES.new(key, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(message.encode('utf-8'), AES.block_size))
    iv = cipher.iv
    ct = base64.b64encode(iv + ct_bytes).decode('utf-8')
    return ct

def decrypt_message(ciphertext):
    ct = base64.b64decode(ciphertext)
    iv = ct[:16]
    ct = ct[16:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    pt = unpad(cipher.decrypt(ct), AES.block_size)
    return pt.decode('utf-8')

clients = {}  # Dictionary to store client connections and usernames

# Broadcast message to all clients except the sender
def broadcast(message, sender_conn):
    for client in clients:
        if clients[client] != sender_conn:  # Don't send the message back to the sender
            try:
                clients[client].send(message)
            except:
                clients[client].close()
                del clients[client]

# Handle private messaging
def send_private_message(username, message):
    if username in clients:
        try:
            clients[username].send(message)
        except:
            clients[username].close()
            del clients[username]
    else:
        print(f"User {username} not found.")

# Function to handle each client
def handle_client(conn, addr):
    print(f"New connection: {addr}")
    
    # Receive the encrypted username
    encrypted_username = conn.recv(1024).decode('utf-8')
    username = decrypt_message(encrypted_username)  # Decrypt the username
    print(f"{username} connected.")
    
    clients[username] = conn  # Add new client to the dictionary
    
    while True:
        try:
            # Receiving message from the client
            ciphertext = conn.recv(1024).decode('utf-8')
            if not ciphertext:
                break
            message = decrypt_message(ciphertext)
            print(f"{username}: {message}")
            
            # Check if the message is a private message (e.g., @username message)
            if message.startswith('@'):
                target_username, private_message = message.split(' ', 1)
                target_username = target_username[1:]  # Remove '@'
                
                # Encrypt and send private message
                encrypted_private_message = encrypt_message(f"{username} (private): {private_message}")
                send_private_message(target_username, encrypted_private_message.encode('utf-8'))
            else:
                # Broadcast the encrypted message to all other clients
                encrypted_message = encrypt_message(f"{username}: {message}")
                broadcast(encrypted_message.encode('utf-8'), conn)
        except:
            break
    
    print(f"{username} disconnected")
    del clients[username]
    conn.close()

# Set up the server to handle multiple clients
def start_server():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(('0.0.0.0', 12345))  # Listen on all network interfaces
    server_socket.listen()

    print("Server is waiting for connections...")
    
    while True:
        conn, addr = server_socket.accept()
        # Start a new thread for each client
        client_thread = threading.Thread(target=handle_client, args=(conn, addr))
        client_thread.start()

# Start the server
start_server()
