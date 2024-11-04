# client.py
import socket
import threading
from tkinter import *
from tkinter import messagebox

PORT = 5050
SERVER = "192.168.56.1"  # Replace with your server IP
ADDRESS = (SERVER, PORT)
FORMAT = "utf-8"

client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.connect(ADDRESS)

class GUI:
    def __init__(self):
        self.Window = Tk()
        self.Window.withdraw()

        self.login = Toplevel()
        self.login.title("Login")
        self.login.configure(width=400, height=300)
        
        Label(self.login, text="Username:", font="Helvetica 12").place(relheight=0.2, relx=0.1, rely=0.2)
        Label(self.login, text="Password:", font="Helvetica 12").place(relheight=0.2, relx=0.1, rely=0.4)
        
        self.username_entry = Entry(self.login, font="Helvetica 14")
        self.username_entry.place(relwidth=0.4, relheight=0.12, relx=0.35, rely=0.2)
        self.password_entry = Entry(self.login, font="Helvetica 14", show="*")
        self.password_entry.place(relwidth=0.4, relheight=0.12, relx=0.35, rely=0.4)
        
        Button(self.login, text="Register", command=self.register).place(relx=0.3, rely=0.7)
        Button(self.login, text="Login", command=self.login_user).place(relx=0.5, rely=0.7)

        self.username = None

        self.Window.mainloop()

    def login_user(self):
        username = self.username_entry.get()
        password = self.password_entry.get()
        client.send(f"LOGIN {username} {password}".encode(FORMAT))
        
        response = client.recv(1024).decode(FORMAT)
        if "successful" in response:
            self.username = username 
            self.login.destroy()
            self.layout(username)
            threading.Thread(target=self.receive).start()
        else:
            messagebox.showerror("Error", response)

    def register(self):
        username = self.username_entry.get()
        password = self.password_entry.get()
        client.send(f"REGISTER {username} {password}".encode(FORMAT))
        
        response = client.recv(1024).decode(FORMAT)
        messagebox.showinfo("Registration", response)

    def layout(self, username):
        self.Window.deiconify()
        self.Window.title("CHATROOM")
        self.Window.configure(width=470, height=550, bg="#17202A")

        Label(self.Window, bg="#17202A", fg="#EAECEE", text=username, font="Helvetica 13 bold", pady=5).place(relwidth=1)
        Label(self.Window, width=450, bg="#ABB2B9").place(relwidth=1, rely=0.07, relheight=0.012)

        self.textCons = Text(self.Window, bg="#17202A", fg="#EAECEE", font="Helvetica 14", padx=5, pady=5)
        self.textCons.place(relheight=0.745, relwidth=1, rely=0.08)
        self.textCons.config(state=DISABLED)

        self.entryMsg = Entry(self.Window, bg="#2C3E50", fg="#EAECEE", font="Helvetica 13")
        self.entryMsg.place(relwidth=0.74, relheight=0.06, rely=0.008, relx=0.011)
        
        Button(self.Window, text="Send", font="Helvetica 10 bold", bg="#ABB2B9", command=lambda: self.send_message()).place(relx=0.77, rely=0.008, relheight=0.06, relwidth=0.22)

    def send_message(self):
        message = f"{self.username}: {self.entryMsg.get()}"
        self.textCons.config(state=NORMAL)
        self.textCons.insert(END, message + "\n\n")
        self.textCons.config(state=DISABLED)
        self.textCons.see(END)
        client.send(message.encode(FORMAT))
        self.entryMsg.delete(0, END)

    def receive(self):
        while True:
            try:
                message = client.recv(1024).decode(FORMAT)
                self.textCons.config(state=NORMAL)
                self.textCons.insert(END, message + "\n\n")
                self.textCons.config(state=DISABLED)
                self.textCons.see(END)

                client.connect(ADDRESS)
            except Exception as e:
                print(f"Connection failed: {e}")
            except:
                print("An error occurred.")
                break



if __name__ == "__main__":
    GUI()