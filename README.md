# Secure Chat Application

This repository contains a **Secure Chat Application** built with Python. It leverages encryption techniques to ensure secure communication between a server and multiple clients.

## Features

- **User Authentication**: Users can sign up and log in with hashed passwords (SHA-256).
- **Encryption**:
  - RSA for exchanging AES keys securely.
  - AES for encrypting messages sent over the network.
- **Multi-client Support**: The server can handle multiple clients simultaneously.
- **Threaded Communication**: Both server and client are multithreaded for asynchronous handling of connections and messages.
- **Debug Logging**: Server-side debug logs for RSA and AES decryption.

## File Overview

### `client.py`

The client-side script performs the following:
- User authentication (sign-up or log-in).
- RSA key pair generation and storage.
- Connects to the server and sends encrypted messages.
- Decrypts messages received from the server.

### `server.py`

The server-side script performs the following:
- Listens for incoming client connections.
- Manages client nicknames and prevents duplicate logins.
- Broadcasts decrypted messages to all connected clients.
- Handles message decryption with RSA and AES.

## Requirements

Ensure you have the following installed:

- Python 3.8+
- `pycryptodome` for cryptographic operations:
  ```bash
  pip install pycryptodome
  ```

## Setup

### 2. Generate Required Files
- Create a `users.txt` file for storing user credentials.
- Create a `servers.json` file to define server configurations. Example:
  ```json
  {
      "TestServer": {
          "ip": "127.0.0.1",
          "port": 5555
      }
  }
  ```

### 3. Run the Server
```bash
python server.py
```

### 4. Run the Client
```bash
python client.py
```

## Usage

### Signing Up
- When prompted, choose the sign-up option.
- Provide a unique username and a strong password (at least 8 characters, including letters and numbers).

### Logging In
- Choose the log-in option.
- Provide your username and password.

### Messaging
- After authentication, connect to a server (from `servers.json`).
- Type messages to send them securely to all other connected clients.

## Security Details

- **Password Security**: SHA-256 hashing ensures that passwords are securely stored.
- **Message Encryption**: Messages are encrypted using a randomly generated AES key, which is securely transmitted using RSA.
- **Key Management**: RSA keys are generated per user and stored locally as `.pem` files.

## Debugging and Logs
The server script (`server.py`) logs decryption processes for troubleshooting purposes. Use these logs to verify encryption and decryption workflows.
