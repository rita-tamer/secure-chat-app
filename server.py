# server.py
import socket
import threading
from database_functions import register_user, login_user, save_message

PORT = 5050
SERVER = "0.0.0.0"
# SERVER = socket.gethostbyname(socket.gethostname())
ADDRESS = (SERVER, PORT)
FORMAT = "utf-8"

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind(ADDRESS)

clients = []

def broadcast(message, client_socket):
    for client in clients:
        if client != client_socket:
            try:
                client.send(message.encode(FORMAT))
            except:
                client.close()
                clients.remove(client)

def handle_client(client_socket):
    while True:
        try:
            message = client_socket.recv(1024).decode(FORMAT)
            
            if message.startswith("REGISTER"):
                _, username, password = message.split()  # Expects "REGISTER <username> <password>"
                if register_user(username, password):
                    client_socket.send("Registration successful!".encode(FORMAT))
                else:
                    client_socket.send("Username already exists.".encode(FORMAT))

            elif message.startswith("LOGIN"):
                _, username, password = message.split()  # Expects "LOGIN <username> <password>"
                if login_user(username, password):
                    client_socket.send("Login successful!".encode(FORMAT))
                    clients.append(client_socket)
                else:
                    client_socket.send("Invalid username or password.".encode(FORMAT))

            else:
                broadcast(message, client_socket)
                sender, content = message.split(": ", 1)
                save_message(sender, "all", content)
        
        except Exception as e:
            print(f"Error: {e}")
            clients.remove(client_socket)
            break

    client_socket.close()

def start():
    server.listen()
    print("Server is running and listening...")
    while True:
        client_socket, _ = server.accept()
        print("Connected with a client.")
        thread = threading.Thread(target=handle_client, args=(client_socket,))
        thread.start()
        
if __name__ == "__main__":
    start()
