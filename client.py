import socket
import threading
import json
import os

def enter_server():
    os.system('cls||clear')
    with open('servers.json') as f:
        data = json.load(f)
    print('Your servers: ', end="")
    for servers in data:
        print(servers, end=" ")
    server_name = input("\nEnter the server name:")
    global nickname
    nickname = input("Choose Your Nickname:")

    ip = data[server_name]["ip"]
    port = data[server_name]["port"]
    global client
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect((ip, port))

def add_server():
    os.system('cls||clear')
    server_name = input("Enter a name for the server:")
    server_ip = input("Enter the ip address of the server:")
    server_port = int(input("Enter the port number of the server:"))

    with open('servers.json', 'r') as f:
        data = json.load(f)
    with open('servers.json', 'w') as f:
        data[server_name] = {"ip": server_ip, "port": server_port}
        json.dump(data, f, indent=4)

while True:
    os.system('cls||clear')
    option = input("(1)Enter server\n(2)Add server\n")
    if option == '1':
        enter_server()
        break
    elif option == '2':
        add_server()

stop_thread = False

def receive():
    while True:
        global stop_thread
        if stop_thread:
            break
        try:
            message = client.recv(1024).decode('ascii')
            if message == 'NICK':
                client.send(nickname.encode('ascii'))
            else:
                print(message)
        except socket.error:
            print('Error Occurred while Connecting')
            client.close()
            break

def write():
    while True:
        if stop_thread:
            break
        message = f'{nickname}: {input("")}'
        client.send(message.encode('ascii'))

receive_thread = threading.Thread(target=receive)
receive_thread.start()
write_thread = threading.Thread(target=write)
write_thread.start()