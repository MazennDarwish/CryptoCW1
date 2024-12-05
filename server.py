import threading
import socket
import os
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Cipher import AES
import base64

host = "127.0.0.1"
port = 5555

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind((host, port))
server.listen()

clients = []
nicknames = []

# Load RSA private key from disk
def load_private_key(nickname):
    with open(f"{nickname}_private.pem", "rb") as f:
        return RSA.import_key(f.read())

# Decrypt AES key with RSA private key
def decrypt_aes_key(encrypted_aes_key, private_key):
    cipher = PKCS1_OAEP.new(private_key)
    decrypted_key = cipher.decrypt(base64.b64decode(encrypted_aes_key))
    print(f"[DEBUG] RSA Decryption - Encrypted AES Key: {encrypted_aes_key}, Decrypted AES Key: {decrypted_key.hex()}")
    return decrypted_key

# Decrypt message with AES
def decrypt_message(encrypted_message, aes_key):
    data = base64.b64decode(encrypted_message)
    nonce, tag, ciphertext = data[:16], data[16:32], data[32:]
    cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
    decrypted = cipher.decrypt_and_verify(ciphertext, tag).decode('utf-8')
    print(f"[DEBUG] AES Decryption - Ciphertext: {encrypted_message}, Plaintext: {decrypted}")
    return decrypted

# Broadcast messages to all clients
def broadcast(message, sender=None):
    for client in clients:
        if client != sender:  # Avoid sending messages back to the sender
            client.send(message)

# Handle incoming messages from clients
def handle(client):
    while True:
        try:
            # Receive message
            message = client.recv(1024).decode('utf-8')
            if message:  # Ensure message is not empty
                encrypted_aes_key, encrypted_message = message.split(':')
                index = clients.index(client)
                private_key = load_private_key(nicknames[index])
                aes_key = decrypt_aes_key(encrypted_aes_key, private_key)
                decrypted_message = decrypt_message(encrypted_message, aes_key)

                # Broadcast the decrypted message to all other clients
                broadcast(f"{nicknames[index]}: {decrypted_message}".encode('utf-8'), sender=client)
        except Exception as e:
            print(f"Error: {e}")
            # Remove disconnected client
            if client in clients:
                index = clients.index(client)
                clients.remove(client)
                client.close()
                nickname = nicknames[index]
                nicknames.remove(nickname)
                broadcast(f"{nickname} left the chat!".encode('utf-8'))
            break

# Accept new client connections
def receive():
    while True:
        client, address = server.accept()
        print(f"Connected with {str(address)}")

        # Step 2: Receive the nickname
        nickname = client.recv(1024).decode('utf-8')

        # Duplicate nickname check
        if nickname in nicknames:
            client.send("REFUSE".encode('utf-8'))
            client.close()
            continue

        # Add client and notify others
        nicknames.append(nickname)
        clients.append(client)
        print(f'Nickname of the client is {nickname}')
        broadcast(f"{nickname} joined the chat!".encode('utf-8'))
        client.send("Connected to the Server!".encode('utf-8'))

        # Start thread for handling messages from this client
        thread = threading.Thread(target=handle, args=(client,))
        thread.start()

print("Server is listening...")
receive()
