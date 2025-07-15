# import sqlite3
# from cryptography import x509
# from cryptography.hazmat.primitives import serialization  # Import serialization for Encoding

# def init_db():
#     conn = sqlite3.connect('voting_system.db')
#     c = conn.cursor()
#     c.execute('''CREATE TABLE IF NOT EXISTS users (
#         id INTEGER PRIMARY KEY AUTOINCREMENT,
#         full_name TEXT NOT NULL,
#         username TEXT UNIQUE NOT NULL,
#         password TEXT NOT NULL,
#         dob TEXT NOT NULL,
#         email TEXT NOT NULL,
#         voter_id TEXT NOT NULL,
#         private_key BLOB NOT NULL,
#         public_key BLOB NOT NULL,
#         certificate BLOB NOT NULL
#     )''')
#     c.execute('''CREATE TABLE IF NOT EXISTS votes (
#         id INTEGER PRIMARY KEY AUTOINCREMENT,
#         user_id INTEGER,
#         candidate TEXT NOT NULL,
#         signature BLOB NOT NULL,
#         certificate BLOB NOT NULL,
#         FOREIGN KEY (user_id) REFERENCES users(id)
#     )''')
#     conn.commit()
#     conn.close()

# def register_user(full_name, username, password, dob, email, voter_id, private_key, public_key, certificate):
#     conn = sqlite3.connect('voting_system.db')
#     c = conn.cursor()
#     try:
#         # Serialize private_key, public_key, and certificate to PEM format
#         private_key_pem = private_key.private_bytes(
#             encoding=serialization.Encoding.PEM,
#             format=serialization.PrivateFormat.TraditionalOpenSSL,
#             encryption_algorithm=serialization.NoEncryption()
#         )
#         public_key_pem = public_key.public_bytes(
#             encoding=serialization.Encoding.PEM,
#             format=serialization.PublicFormat.SubjectPublicKeyInfo
#         )
#         certificate_pem = certificate.public_bytes(
#             encoding=serialization.Encoding.PEM
#         )
#         c.execute("INSERT INTO users (full_name, username, password, dob, email, voter_id, private_key, public_key, certificate) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
#                   (full_name, username, password, dob, email, voter_id, private_key_pem, public_key_pem, certificate_pem))
#         conn.commit()
#         print(f"Registered user: {username}")  # Debug print
#     except sqlite3.Error as e:
#         print(f"Database error: {e}")  # Debug error
#         conn.rollback()
#     finally:
#         conn.close()

# def authenticate_user(username, password):
#     conn = sqlite3.connect('voting_system.db')
#     c = conn.cursor()
#     c.execute("SELECT id, username, password FROM users WHERE username = ? AND password = ?", (username, password))
#     user = c.fetchone()
#     conn.close()
#     if user:
#         return {'id': user[0], 'username': user[1], 'password': user[2]}
#     return None

# def store_vote(user_id, candidate, signature, certificate):
#     conn = sqlite3.connect('voting_system.db')
#     c = conn.cursor()
#     try:
#         c.execute("INSERT INTO votes (user_id, candidate, signature, certificate) VALUES (?, ?, ?, ?)",
#                   (user_id, candidate, signature, certificate.public_bytes(serialization.Encoding.PEM)))  # Use serialization.Encoding.PEM
#         conn.commit()
#         print(f"Stored vote for user_id: {user_id}")  # Debug print
#     except sqlite3.Error as e:
#         print(f"Database error: {e}")  # Debug error
#         conn.rollback()
#     finally:
#         conn.close()

# def get_user_certificate(user_id):
#     conn = sqlite3.connect('voting_system.db')
#     c = conn.cursor()
#     c.execute("SELECT private_key, certificate FROM users WHERE id = ?", (user_id,))
#     user = c.fetchone()
#     conn.close()
#     if user:
#         try:
#             private_key = serialization.load_pem_private_key(user[0], password=None)
#             certificate = x509.load_pem_x509_certificate(user[1])
#             return {'private_key': private_key, 'certificate': certificate}
#         except ValueError as e:
#             print(f"Deserialization error: {e}")
#             return None
#     return None

# def get_all_votes():
#     conn = sqlite3.connect('voting_system.db')
#     c = conn.cursor()
#     c.execute("SELECT id, user_id, candidate, signature, certificate FROM votes")
#     votes = c.fetchall()
#     conn.close()
#     return [{'id': v[0], 'user_id': v[1], 'candidate': v[2], 'signature': v[3], 'certificate': v[4]} for v in votes]

# def has_voted(user_id):
#     conn = sqlite3.connect('voting_system.db')
#     c = conn.cursor()
#     c.execute("SELECT id FROM votes WHERE user_id = ?", (user_id,))
#     result = c.fetchone()
#     conn.close()
#     return result is not None

# def get_vote_tally():
#     conn = sqlite3.connect('voting_system.db')
#     c = conn.cursor()
#     c.execute("SELECT candidate, COUNT(*) as count FROM votes GROUP BY candidate")
#     tally = c.fetchall()
#     conn.close()
#     return {candidate: count for candidate, count in tally}



import sqlite3
from cryptography import x509 # type: ignore
from cryptography.hazmat.primitives import serialization # type: ignore
import bcrypt # Import bcrypt
from crypto_utils import decrypt_private_key, encrypt_private_key # Import necessary crypto_utils functions

def init_db():
    conn = sqlite3.connect('voting_system.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        full_name TEXT NOT NULL,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        dob TEXT NOT NULL,
        email TEXT NOT NULL,
        voter_id TEXT NOT NULL,
        private_key BLOB NOT NULL,
        public_key BLOB NOT NULL,
        certificate BLOB NOT NULL
    )''')
    c.execute('''CREATE TABLE IF NOT EXISTS votes (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        candidate TEXT NOT NULL,
        signature BLOB NOT NULL,
        certificate BLOB NOT NULL,
        FOREIGN KEY (user_id) REFERENCES users(id)
    )''')
    conn.commit()
    conn.close()

def register_user(full_name, username, password, dob, email, voter_id, encrypted_private_key_bundle, public_key_pem, certificate_pem):
    conn = sqlite3.connect('voting_system.db')
    c = conn.cursor()
    try:
        # Hash the password
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        
        c.execute("INSERT INTO users (full_name, username, password, dob, email, voter_id, private_key, public_key, certificate) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                  (full_name, username, hashed_password, dob, email, voter_id, encrypted_private_key_bundle, public_key_pem, certificate_pem))
        conn.commit()
        print(f"Registered user: {username}")
    except sqlite3.Error as e:
        print(f"Database error during registration: {e}")
        conn.rollback()
        raise # Re-raise the exception to be caught in main.py
    finally:
        conn.close()

def authenticate_user(username, password):
    conn = sqlite3.connect('voting_system.db')
    c = conn.cursor()
    c.execute("SELECT id, username, password FROM users WHERE username = ?", (username,))
    user = c.fetchone()
    conn.close()
    if user:
        # Verify the password
        if bcrypt.checkpw(password.encode('utf-8'), user[2].encode('utf-8')):
            return {'id': user[0], 'username': user[1], 'password': user[2]}
    return None

def store_vote(user_id, candidate, signature, certificate_pem): # Changed certificate to certificate_pem
    conn = sqlite3.connect('voting_system.db')
    c = conn.cursor()
    try:
        c.execute("INSERT INTO votes (user_id, candidate, signature, certificate) VALUES (?, ?, ?, ?)",
                  (user_id, candidate, signature, certificate_pem)) # Store PEM bytes
        conn.commit()
        print(f"Stored vote for user_id: {user_id}")
    except sqlite3.Error as e:
        print(f"Database error during vote storage: {e}")
        conn.rollback()
    finally:
        conn.close()

def get_user_certificate(user_id, password): # Added password parameter
    conn = sqlite3.connect('voting_system.db')
    c = conn.cursor()
    c.execute("SELECT private_key, certificate FROM users WHERE id = ?", (user_id,))
    user = c.fetchone()
    conn.close()
    if user:
        try:
            # user[0] is the encrypted private key bundle (BLOB)
            private_key = decrypt_private_key(user[0], password) # Decrypt with provided password
            certificate = x509.load_pem_x509_certificate(user[1])
            return {'private_key': private_key, 'certificate': certificate}
        except ValueError as e:
            print(f"Deserialization or decryption error: {e}")
            return None
        except Exception as e:
            print(f"Error fetching user certificate: {e}")
            return None
    return None

def get_all_votes():
    conn = sqlite3.connect('voting_system.db')
    c = conn.cursor()
    c.execute("SELECT id, user_id, candidate, signature, certificate FROM votes")
    votes = c.fetchall()
    conn.close()
    # certificates are stored as BLOB (PEM bytes), so no need to serialize/deserialize here
    return [{'id': v[0], 'user_id': v[1], 'candidate': v[2], 'signature': v[3], 'certificate': v[4]} for v in votes]

def has_voted(user_id):
    conn = sqlite3.connect('voting_system.db')
    c = conn.cursor()
    c.execute("SELECT id FROM votes WHERE user_id = ?", (user_id,))
    result = c.fetchone()
    conn.close()
    return result is not None

def get_vote_tally():
    conn = sqlite3.connect('voting_system.db')
    c = conn.cursor()
    c.execute("SELECT candidate, COUNT(*) as count FROM votes GROUP BY candidate")
    tally = c.fetchall()
    conn.close()
    return {candidate: count for candidate, count in tally}