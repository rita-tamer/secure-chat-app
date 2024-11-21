import socket
import threading
from database_functions import register_user, login_user, save_message, store_public_key, save_shared_key, get_shared_key
from encryption_utils import EncryptionUtils

PORT = 5050
SERVER = "0.0.0.0"
ADDRESS = (SERVER, PORT)
FORMAT = "utf-8"

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind(ADDRESS)

clients = []  # List of connected client sockets
client_keys = {}  # Mapping of client socket to public key
shared_keys = {}  # Dynamic mapping of (user1, user2) -> shared key

def compute_shared_key(public_key_1, private_key_2, prime):
    """Compute the shared key using Diffie-Hellman."""
    return pow(public_key_1, private_key_2, prime)

def broadcast(message, sender_socket=None):
    """Broadcast a message to all connected clients except the sender."""
    for client in clients.copy():
        if client != sender_socket:
            try:
                client.send(message.encode(FORMAT))
            except Exception as e:
                print(f"Error broadcasting message: {e}")
                client.close()
                if client in clients:
                    clients.remove(client)

def handle_client(client_socket):
    """Handle communication with a connected client."""
    global shared_keys  # Declare shared_keys as global
    try:
        username = None  # To track the client's username
        encryption = EncryptionUtils()  # Local encryption object for Diffie-Hellman operations

        while True:
            message = client_socket.recv(4096).decode(FORMAT)
            if not message:
                break

            if message.startswith("REGISTER"):
                try:
                    _, username, password = message.split(" ", 2)
                    if register_user(username, password):
                        client_socket.send("REGISTER_SUCCESS".encode(FORMAT))
                    else:
                        client_socket.send("REGISTER_FAIL".encode(FORMAT))
                except ValueError:
                    print(f"Malformed REGISTER message: {message}")
                    client_socket.send("REGISTER_FAIL".encode(FORMAT))

            elif message.startswith("LOGIN"):
                try:
                    _, username, password = message.split(" ", 2)
                    if login_user(username, password):
                        client_socket.send("LOGIN_SUCCESS".encode(FORMAT))
                        clients.append(client_socket)
                    else:
                        client_socket.send("LOGIN_FAIL".encode(FORMAT))
                except ValueError:
                    print(f"Malformed LOGIN message: {message}")
                    client_socket.send("LOGIN_FAIL".encode(FORMAT))

            elif message.startswith("PUBLIC_KEY:"):
                try:
                    parts = message.split(":")
                    if len(parts) != 3:
                        raise ValueError("Malformed PUBLIC_KEY message")
                    username = parts[1]
                    public_key = int(parts[2])
                    store_public_key(username, public_key)  # Save public key in the database
                    print(f"Stored public key for {username}: {public_key}")

                    # Add public key to client_keys
                    client_keys[client_socket] = (username, public_key)

                    # Compute shared keys with all other clients
                    for other_client, (other_username, other_public_key) in client_keys.items():
                        if other_client != client_socket:
                            shared_key = compute_shared_key(public_key, other_public_key, encryption.prime)
                            shared_key_bytes = shared_key.to_bytes(16, 'big')[:16]  # Convert to 16-byte AES key
                            shared_keys[(username, other_username)] = shared_key_bytes
                            # Save shared key in the database
                            save_shared_key(username, other_username, shared_key_bytes.hex())  # Store as hex
                            print(f"Computed and saved shared key for {username} and {other_username}")

                    # Notify clients when all keys are exchanged
                    if len(client_keys) == len(clients):
                        broadcast("ALL_KEYS_READY")
                except ValueError as e:
                    print(f"Error processing PUBLIC_KEY: {e}. Message: {message}")

            elif message.startswith("FETCH_SHARED_KEY:"):
                try:
                    # Extract the requesting username
                    requesting_username = message.split(":")[1]
                    
                    # Find the shared key for the requesting client
                    shared_key = None
                    for other_client, (other_username, _) in client_keys.items():
                        if other_client != client_socket:
                            # Retrieve the shared key for this user pair
                            shared_key = get_shared_key(requesting_username, other_username)
                            if shared_key:
                                # Send the shared key back to the client
                                client_socket.send(shared_key.encode(FORMAT))
                                print(f"Sent shared key to {requesting_username} for {other_username}")
                                break  # Exit after sending the shared key
                            
                    if not shared_key:
                        print(f"No shared key found for {requesting_username}.")
                except Exception as e:
                    print(f"Error fetching shared key: {e}")
                    
            elif message.startswith("MESSAGE:"):
                # Extract the encrypted message from the prefix and broadcast it
                encrypted_message = message[len("MESSAGE:"):]  # Remove "MESSAGE:" prefix
                broadcast(encrypted_message, sender_socket=client_socket)

    except Exception as e:
        print(f"Error: {e}")

    finally:
        # Cleanup on disconnection
        if username:
            # Remove all shared keys involving this user
            shared_keys = {k: v for k, v in shared_keys.items() if username not in k}
        if client_socket in clients:
            clients.remove(client_socket)
            client_keys.pop(client_socket, None)
        client_socket.close()

def start():
    """Start the server and listen for incoming connections."""
    server.listen()
    print(f"Server running on {SERVER}:{PORT}")
    while True:
        client_socket, _ = server.accept()
        print("New connection")
        thread = threading.Thread(target=handle_client, args=(client_socket,))
        thread.start()

if __name__ == "__main__":
    start()
