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
                print(f"Received raw message: {message}")  # Log the raw received message
    
                if message.startswith("PUBLIC_KEY:"):
                    # Handle public key reception
                    other_public_key = int(message.split(":")[2])
                    encryption.compute_shared_key(other_public_key)
                    print("Shared key computed successfully!")
    
                elif message == "ALL_KEYS_READY":
                    print("Received ALL_KEYS_READY signal. Fetching shared key.")
                    client.send(f"FETCH_SHARED_KEY:{self.username}".encode(FORMAT))
                    shared_key = client.recv(4096).decode(FORMAT)
                    print(f"Received shared key: {shared_key}")  # Log received shared key
    
                    if shared_key and all(c in "0123456789abcdefABCDEF" for c in shared_key):
                        try:
                            encryption.shared_key = bytes.fromhex(shared_key)
                            shared_key_ready = True
                            print("Shared key successfully set.")
                        except ValueError as e:
                            print(f"Error setting shared key: {e}")
                            messagebox.showerror("Error", "Failed to parse shared key.")
                    else:
                        print(f"Invalid shared key format received: {shared_key}")
                        messagebox.showerror("Error", "Received invalid shared key format!")
    
                elif message.startswith("MESSAGE:"):
                    parts = message.split(":")
                    if len(parts) != 4:
                        print(f"Malformed message received: {message}")
                        continue
                    
                    iv_b64, ciphertext_b64, tag_b64 = parts[1], parts[2], parts[3]
                    decrypted_message = encryption.decrypt(iv_b64, ciphertext_b64, tag_b64)
                    if decrypted_message:
                        print(f"Decrypted message: {decrypted_message}")
                        self.textCons.config(state=NORMAL)
                        self.textCons.insert(END, decrypted_message + "\n")
                        self.textCons.config(state=DISABLED)
                    else:
                        print("Failed to decrypt message!")
                        messagebox.showerror("Error", "Decryption failed. Please check encryption setup.")
                else:
                    print(f"Malformed message received: {message}")
            except Exception as e:
                print(f"Error: {e}")
                break

    def send_message(self):
        """Encrypt and send a message."""
        global shared_key_ready
        if not shared_key_ready:
            messagebox.showwarning("Error", "The key is not set yet!")
            return
    
        message = self.entryMsg.get()
        if message:
            # Encrypt the message
            iv, ciphertext, tag = encryption.encrypt(f"{self.username}: {message}")
            message_to_send = f"MESSAGE:{iv}:{ciphertext}:{tag}"
            print(f"Sending message: {message_to_send}")  # Log the outgoing message
            client.send(message_to_send.encode(FORMAT))
            self.entryMsg.delete(0, END)

if __name__ == "__main__":
    GUI()
