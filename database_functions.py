# database_functions.py
import sqlite3
from hashlib import sha256

def hash_password(password):
    return sha256(password.encode()).hexdigest()

def register_user(username, password):
    conn = sqlite3.connect("chat_app.db")
    cursor = conn.cursor()
    hashed_pw = hash_password(password)
    
    try:
        cursor.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, hashed_pw))
        conn.commit()
        return True  # Registration successful
    except sqlite3.IntegrityError:
        return False  # Username already exists
    finally:
        conn.close()

def login_user(username, password):
    conn = sqlite3.connect("chat_app.db")
    cursor = conn.cursor()
    hashed_pw = hash_password(password)
    
    cursor.execute("SELECT * FROM users WHERE username = ? AND password = ?", (username, hashed_pw))
    user = cursor.fetchone()
    conn.close()
    return user is not None  # True if login is successful

def save_message(sender, receiver, content):
    conn = sqlite3.connect("chat_app.db")
    cursor = conn.cursor()
    cursor.execute("INSERT INTO messages (sender, receiver, content) VALUES (?, ?, ?)", (sender, receiver, content))
    conn.commit()
    conn.close()
