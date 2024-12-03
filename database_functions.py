import sqlite3
import os
from hashlib import sha256

# Fixed secret pepper (must remain constant)
PEPPER = "secret-pepper-key"

def hash_password(password, salt):
    """Hash the password with salt and pepper."""
    return sha256((password + salt + PEPPER).encode()).hexdigest()

def register_user(username, password):
    """Register a new user with a hashed password and a salt."""
    conn = sqlite3.connect("chat_app.db")
    cursor = conn.cursor()
    
    # Generate a unique salt for the user
    salt = os.urandom(16).hex()
    hashed_pw = hash_password(password, salt)
    
    try:
        cursor.execute("INSERT INTO users (username, password, salt) VALUES (?, ?, ?)", (username, hashed_pw, salt))
        conn.commit()
        return True  # Registration successful
    except sqlite3.IntegrityError:
        return False  # Username already exists
    finally:
        conn.close()

def login_user(username, password):
    """Login a user by checking if the password matches."""
    conn = sqlite3.connect("chat_app.db")
    cursor = conn.cursor()
    
    # Fetch user's salt and hashed password
    cursor.execute("SELECT password, salt FROM users WHERE username = ?", (username,))
    result = cursor.fetchone()
    
    if not result:
        conn.close()
        return False  # User not found
    
    stored_hashed_pw, salt = result
    conn.close()
    
    # Hash the provided password with the stored salt and pepper
    hashed_pw = hash_password(password, salt)
    return hashed_pw == stored_hashed_pw

def save_message(sender, receiver, content):
    """Store encrypted messages in the database."""
    conn = sqlite3.connect("chat_app.db")
    cursor = conn.cursor()
    cursor.execute("INSERT INTO messages (sender, receiver, content) VALUES (?, ?, ?)", (sender, receiver, content))
    conn.commit()
    conn.close()

def username_exists(username):
    """Check if the username already exists in the database."""
    conn = sqlite3.connect('chat_app.db')
    c = conn.cursor()
    c.execute('''SELECT 1 FROM users WHERE username = ?''', (username,))
    exists = c.fetchone()
    conn.close()
    return exists is not None

def get_public_key(username):
    """Retrieve the public key of a user."""
    conn = sqlite3.connect('chat_app.db')
    c = conn.cursor()
    c.execute('''SELECT public_key FROM users WHERE username = ?''', (username,))
    public_key = c.fetchone()
    conn.close()
    if public_key:
        return public_key[0]
    else:
        return None

def store_public_key(username, public_key):
    """Store or update the user's public key in the database."""
    conn = sqlite3.connect('chat_app.db')
    cursor = conn.cursor()
    try:
        cursor.execute('''
            UPDATE users SET public_key = ? WHERE username = ?
        ''', (public_key, username))
        if cursor.rowcount == 0:  # No rows were updated, insert instead
            cursor.execute('''
                INSERT INTO users (username, public_key) VALUES (?, ?)
            ''', (username, public_key))
        conn.commit()
        print(f"Public key for {username} stored successfully!")
    except sqlite3.Error as e:
        print(f"Database error while storing public key: {e}")
    finally:
        conn.close()

def save_shared_key(user1, user2, shared_key):
    """Save the shared key in the database."""
    conn = sqlite3.connect("chat_app.db")
    cursor = conn.cursor()

    # Sort user names to avoid duplicate entries for the same pair
    users = sorted([user1, user2])
    try:
        cursor.execute('''
            INSERT OR REPLACE INTO shared_keys (user1, user2, shared_key)
            VALUES (?, ?, ?)
        ''', (users[0], users[1], shared_key))
        conn.commit()
        print(f"Shared key for {users[0]} and {users[1]} saved successfully!")
    except sqlite3.Error as e:
        print(f"Database error while saving shared key: {e}")
    finally:
        conn.close()

def get_shared_key(user1, user2):
    """Retrieve the shared key for two users."""
    conn = sqlite3.connect("chat_app.db")
    cursor = conn.cursor()

    # Sort user names to match insertion order
    users = sorted([user1, user2])
    try:
        cursor.execute('''
            SELECT shared_key FROM shared_keys WHERE user1 = ? AND user2 = ?
        ''', (users[0], users[1]))
        result = cursor.fetchone()
        if result:
            return result[0]
        else:
            print(f"No shared key found for {users[0]} and {users[1]}")
            return None
    except sqlite3.Error as e:
        print(f"Database error while retrieving shared key: {e}")
        return None
    finally:
        conn.close()
        
def store_message(sender, receiver, encrypted_message):
    """Store an encrypted message in the database."""
    conn = sqlite3.connect('chat_app.db')
    cursor = conn.cursor()
    try:
        cursor.execute('''
            INSERT INTO messages (sender, receiver, encrypted_message)
            VALUES (?, ?, ?)
        ''', (sender, receiver, encrypted_message))
        conn.commit()
        print(f"Message from {sender} to {receiver} stored successfully!")
    except sqlite3.Error as e:
        print(f"Database error while storing message: {e}")
    finally:
        conn.close()

def fetch_messages(receiver):
    """Fetch all messages for a specific receiver."""
    conn = sqlite3.connect('chat_app.db')
    cursor = conn.cursor()
    try:
        cursor.execute('''
            SELECT sender, encrypted_message
            FROM messages
            WHERE receiver = ?
        ''', (receiver,))
        messages = cursor.fetchall()
        print(f"Fetched {len(messages)} messages for {receiver}.")
        return messages
    except sqlite3.Error as e:
        print(f"Database error while fetching messages: {e}")
        return []
    finally:
        conn.close()