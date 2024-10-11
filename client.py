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

# Function to receive messages from the server
def receive_messages(client_socket):
    while True:
        try:
            # Receive and decrypt the message
            encrypted_message = client_socket.recv(1024).decode('utf-8')
            if encrypted_message:
                message = decrypt_message(encrypted_message)
                print(message)  # Display the message
        except:
            print("An error occurred! Closing connection.")
            client_socket.close()
            break

# Function to send messages to the server
def send_messages(client_socket):
    while True:
        try:
            # Take user input and send encrypted message
            message = input()  # Use format @username message to send private message
            if message:
                encrypted_message = encrypt_message(message)
                client_socket.send(encrypted_message.encode('utf-8'))
        except:
            print("An error occurred while sending the message.")
            client_socket.close()
            break

# Connect to the server
client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_socket.connect(('127.0.0.1', 12345))  # Use the server's IP address here

# Set a username
username = input("Enter your username: ")
client_socket.send(encrypt_message(username).encode('utf-8'))

# Start a thread to continuously receive messages from the server
receive_thread = threading.Thread(target=receive_messages, args=(client_socket,))
receive_thread.daemon = True  # Daemon mode so the thread closes when the program exits
receive_thread.start()

# Start a loop to send messages to the server
send_messages(client_socket)
