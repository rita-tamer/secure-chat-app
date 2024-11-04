# database_setup.py
import sqlite3

def initialize_db():
    conn = sqlite3.connect("chat_app.db")
    cursor = conn.cursor()
    
    # Create users table
    cursor.execute('''CREATE TABLE IF NOT EXISTS users (
                        id INTEGER PRIMARY KEY,
                        username TEXT UNIQUE,
                        password TEXT
                     )''')
    
    # Create messages table
    cursor.execute('''CREATE TABLE IF NOT EXISTS messages (
                        id INTEGER PRIMARY KEY,
                        sender TEXT,
                        receiver TEXT,
                        content TEXT,
                        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
                     )''')
    
    conn.commit()
    conn.close()

if __name__ == "__main__":
    initialize_db()
