import sqlite3

# Function to initialize the database and create necessary tables
def initialize_db():
    conn = sqlite3.connect("chat_app.db")
    cursor = conn.cursor()
    
    # Create 'users' table with username, public_key, password (hashed), and salt
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            username TEXT UNIQUE,
            public_key INTEGER,
            password TEXT,
            salt TEXT
        )
    ''')
    
    # Create 'messages' table to store encrypted chat messages
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sender TEXT NOT NULL,
            receiver TEXT NOT NULL,
            encrypted_message TEXT NOT NULL,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    """)

    # Create shared keys table
    cursor.execute('''
            CREATE TABLE IF NOT EXISTS shared_keys (
                id INTEGER PRIMARY KEY,
                user1 TEXT,
                user2 TEXT,
                shared_key TEXT,
                UNIQUE(user1, user2)
            )
        ''')
    
    conn.commit()
    conn.close()

if __name__ == "__main__":
    # Initialize the database and create tables
    initialize_db()
    print("Database and tables have been set up successfully!")
