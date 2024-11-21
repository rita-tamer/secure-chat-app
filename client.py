import socket
import threading
from tkinter import *
from tkinter import messagebox
from encryption_utils import EncryptionUtils

PORT = 5050
SERVER = "192.168.56.1"  # Replace with server IP
ADDRESS = (SERVER, PORT)
FORMAT = "utf-8"

client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.connect(ADDRESS)

# Initialize encryption utilities
encryption = EncryptionUtils()
shared_key_ready = False  # Flag to indicate if the shared key is ready

class GUI:
    def __init__(self):
        self.Window = Tk()
        self.Window.withdraw()

        self.login = Toplevel()
        self.login.title("Login")
        self.login.geometry("400x300")

        Label(self.login, text="Username:").pack()
        self.username_entry = Entry(self.login)
        self.username_entry.pack()

        Label(self.login, text="Password:").pack()
        self.password_entry = Entry(self.login, show="*")
        self.password_entry.pack()

        Button(self.login, text="Register", command=self.register).pack()
        Button(self.login, text="Login", command=self.login_user).pack()

        self.Window.mainloop()

    def login_user(self):
        """Send login request to the server."""
        global shared_key_ready
        username = self.username_entry.get()
        password = self.password_entry.get()
        client.send(f"LOGIN {username} {password}".encode(FORMAT))
        response = client.recv(1024).decode(FORMAT)
        if response == "LOGIN_SUCCESS":
            self.username = username
            encryption.generate_key_pair()  # Generate public/private keys
            # Send public key to the server with the username
            client.send(f"PUBLIC_KEY:{self.username}:{encryption.public_key}".encode(FORMAT))
            self.login.destroy()
            self.layout(username)
            shared_key_ready = False  # Wait for shared key computation
            threading.Thread(target=self.receive).start()  # Start the receiving thread
        else:
            messagebox.showerror("Error", "Login failed!")

    def register(self):
        """Send register request to the server."""
        username = self.username_entry.get()
        password = self.password_entry.get()
        client.send(f"REGISTER {username} {password}".encode(FORMAT))
        response = client.recv(1024).decode(FORMAT)
        if response == "REGISTER_SUCCESS":
            messagebox.showinfo("Success", "Registration successful!")
        else:
            messagebox.showerror("Error", "Registration failed!")

    def layout(self, username):
        """Set up the chat UI."""
        self.Window.deiconify()
        self.Window.title(f"Chatroom - {username}")

        self.textCons = Text(self.Window, state=DISABLED)
        self.textCons.pack(expand=True, fill=BOTH)

        self.entryMsg = Entry(self.Window)
        self.entryMsg.pack(fill=X)

        Button(self.Window, text="Send", command=self.send_message).pack()

    def receive(self):
        """Receive and decrypt messages."""
        global shared_key_ready
        while True:
            try:
                message = client.recv(4096).decode(FORMAT)
                print(f"Received: {message}")  # Debug statement

                if message.startswith("PUBLIC_KEY:"):
                    # Handle public key reception
                    other_public_key = int(message.split(":")[2])
                    encryption.compute_shared_key(other_public_key)
                    print("Shared key computed successfully!")

                elif message == "ALL_KEYS_READY":
                    print("Received ALL_KEYS_READY signal. Fetching shared key.")
                    client.send(f"FETCH_SHARED_KEY:{self.username}".encode(FORMAT))

                    # Receive the shared key from the server
                    shared_key = client.recv(4096).decode(FORMAT)
                    print(f"Received shared key: {shared_key}")  # Debug statement

                    # Ensure the received shared key is a valid hexadecimal string
                    if shared_key and all(c in "0123456789abcdefABCDEF" for c in shared_key):
                        try:
                            # Convert the hexadecimal string to bytes
                            encryption.shared_key = bytes.fromhex(shared_key)
                            shared_key_ready = True
                            print("Shared key successfully set.")  # Debug statement
                        except ValueError as e:
                            print(f"Error setting shared key: {e}")
                            messagebox.showerror("Error", "Failed to parse shared key.")
                    else:
                        print(f"Invalid shared key format received: {shared_key}")
                        messagebox.showerror("Error", "Received invalid shared key format!")

                elif message.startswith("MESSAGE:"):
                    # Handle encrypted messages
                    encrypted_message = message[len("MESSAGE:"):]
                    decrypted_message = encryption.decrypt(encrypted_message)
                    # decrypted_message = encryption.decrypt(message[len("MESSAGE:"):])  # Decrypt after removing "MESSAGE:" prefix
                    if decrypted_message:
                        self.textCons.config(state=NORMAL)
                        self.textCons.insert(END, decrypted_message + "\n")
                        self.textCons.config(state=DISABLED)
                        self.textCons.after(0, self.insert_message, decrypted_message)
                    else:
                        print("Failed to decrypt message!")

            except Exception as e:
                print(f"Error: {e}")
                break
            
    def insert_message(self, message):
        """Insert a message into the Text widget."""
        self.textCons.config(state=NORMAL)
        self.textCons.insert(END, message + "\n")
        self.textCons.config(state=DISABLED)

    def send_message(self):
        """Encrypt and send a message."""
        global shared_key_ready
        if not shared_key_ready:
            messagebox.showwarning("Error", "The key is not set yet!")
            return  # Do not send a message until the key is ready

        message = self.entryMsg.get()
        if message:
            encrypted_message = encryption.encrypt(f"{self.username}: {message}")
            message_to_send = f"MESSAGE:{encrypted_message}"
            client.send(message_to_send.encode(FORMAT))
            self.entryMsg.delete(0, END)

if __name__ == "__main__":
    GUI()
