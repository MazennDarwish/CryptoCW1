import socket
import threading
import json
import os
import hashlib
import re
import base64
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Random import get_random_bytes

# File to store user credentials
USER_FILE = 'users.txt'

# Global variables for client
nickname = ''
client = None
stop_thread = False

# Hashing password with SHA-256
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

# Validate password: At least 8 characters and includes both letters and numbers
def is_valid_password(password):
    if len(password) < 8:
        return False
    if not re.search(r'[A-Za-z]', password):  # At least one letter
        return False
    if not re.search(r'\d', password):  # At least one number
        return False
    return True

# Check if the username already exists
def username_exists(username):
    if not os.path.exists(USER_FILE):
        return False

    with open(USER_FILE, 'r') as f:
        for line in f:
            stored_username, _ = line.strip().split(',')
            if username == stored_username:
                return True
    return False

# Generate RSA key pair and store them
def generate_rsa_keys(username):
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()

    with open(f"{username}_private.pem", "wb") as f:
        f.write(private_key)

    with open(f"{username}_public.pem", "wb") as f:
        f.write(public_key)

# Load RSA public key from disk
def load_public_key(username):
    with open(f"{username}_public.pem", "rb") as f:
        return RSA.import_key(f.read())

# Load RSA private key from disk
def load_private_key(username):
    with open(f"{username}_private.pem", "rb") as f:
        return RSA.import_key(f.read())

# Sign-up function to register new users
def signup(username, password):
    if username_exists(username):
        print("Username already exists. Please choose a different username.")
        return False

    if not is_valid_password(password):
        print("Password must be at least 8 characters long and include both letters and numbers.")
        return False

    hashed_password = hash_password(password)

    # Save credentials to users.txt
    with open(USER_FILE, 'a') as f:
        f.write(f"{username},{hashed_password}\n")
    generate_rsa_keys(username)  # Generate and store RSA keys
    print("Sign-up successful.")
    return True

# Login function to authenticate users
def login(username, password):
    hashed_password = hash_password(password)

    # Check credentials
    with open(USER_FILE, 'r') as f:
        for line in f:
            stored_username, stored_hashed_password = line.strip().split(',')
            if username == stored_username and hashed_password == stored_hashed_password:
                print("Login successful.")
                return True
    print("Invalid credentials!")
    return False

# User authentication (Sign up or Log in)
def authenticate(username, password, is_signup=False):
    if not os.path.exists(USER_FILE):
        open(USER_FILE, 'w').close()  # Create the user file if it doesn't exist

    if is_signup:
        return signup(username, password)  # Register a new user
    else:
        return login(username, password)  # Log in user

# Encrypt message with AES
def encrypt_message(message, key):
    cipher = AES.new(key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(message.encode())
    return base64.b64encode(cipher.nonce + tag + ciphertext).decode('utf-8')

# Decrypt message with AES
def decrypt_message(encrypted_message, key):
    data = base64.b64decode(encrypted_message)
    nonce, tag, ciphertext = data[:16], data[16:32], data[32:]
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    return cipher.decrypt_and_verify(ciphertext, tag).decode('utf-8')

# Encrypt AES key with RSA public key
def encrypt_aes_key(aes_key, public_key):
    cipher = PKCS1_OAEP.new(public_key)
    return base64.b64encode(cipher.encrypt(aes_key)).decode('utf-8')

# Connect to server and authenticate
def enter_server(username, server_name):
    global nickname, client
    nickname = username  # Set nickname as the logged-in username

    with open('servers.json') as f:
        data = json.load(f)
    ip = data[server_name]["ip"]
    port = data[server_name]["port"]

    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect((ip, port))

    # Send the nickname to the server in plain UTF-8 format
    client.send(nickname.encode('utf-8'))
    print(f"Connected to {server_name}.")

# Send message to server
def write():
    aes_key = get_random_bytes(16)  # Generate AES key
    public_key = load_public_key(nickname)

    while True:
        if stop_thread:
            break
        message = input(f"{nickname}: ")
        encrypted_message = encrypt_message(message, aes_key)
        encrypted_aes_key = encrypt_aes_key(aes_key, public_key)
        # Send the AES-encrypted message and the RSA-encrypted AES key
        client.send(f"{encrypted_aes_key}:{encrypted_message}".encode('utf-8'))

# Receive and display messages from server
def receive():
    while True:
        try:
            message = client.recv(1024).decode('utf-8')
            if message:
                print(f"\n{message}")  # Force a newline before displaying
        except:
            print("\nError occurred. Disconnected.")
            client.close()
            break


# Main function to handle interactions with the terminal
def main():
    while True:
        print("Welcome! Please select an option:")
        print("1. Login")
        print("2. Sign Up")
        choice = input("Enter your choice (1/2): ")

        username = input("Enter username: ")
        password = input("Enter password: ")

        if choice == '1' and authenticate(username, password, is_signup=False):
            break
        elif choice == '2' and authenticate(username, password, is_signup=True):
            break
        else:
            print("Invalid input. Please try again.")

    with open('servers.json') as f:
        data = json.load(f)

    print("\nAvailable servers:")
    for server_name in data:
        print(server_name)

    server_name = input("Enter the server name to connect: ")
    if server_name in data:
        enter_server(username, server_name)
    else:
        print("Invalid server name. Exiting.")
        return

    print("Type your messages below:")
    threading.Thread(target=receive).start()
    write()

if __name__ == "__main__":
    main()
