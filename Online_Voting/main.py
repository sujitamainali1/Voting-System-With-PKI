# import os
# import sqlite3
# from flask import Flask, request, render_template, redirect, url_for, flash, session
# from cryptography.hazmat.primitives import serialization
# from cryptography import x509
# from datetime import datetime, timedelta
# from crypto_utils import generate_key_pair, issue_certificate, sign_data, verify_signature
# from database import init_db, register_user, authenticate_user, store_vote, get_user_certificate, get_all_votes, has_voted, get_vote_tally

# app = Flask(__name__)
# app.secret_key = 'supersecretkey123'

# # Initialize database
# init_db()

# @app.route('/')
# def home():
#     return render_template('home.html', authenticated='user_id' in session)

# @app.route('/register', methods=['GET', 'POST'])
# def register():
#     if request.method == 'POST':
#         full_name = request.form['full_name']
#         username = request.form['username']
#         password = request.form['password']
#         confirm_password = request.form['confirm_password']
#         dob = request.form['dob']
#         email = request.form['email']
#         voter_id = request.form['voter_id']

#         # Validate password match
#         if password != confirm_password:
#             flash('Passwords do not match!')
#             return redirect(url_for('register'))

#         # Validate age (must be at least 18)
#         dob_date = datetime.strptime(dob, '%Y-%m-%d')
#         today = datetime.now()
#         age = today.year - dob_date.year - ((today.month, today.day) < (dob_date.month, dob_date.day))
#         if age < 18:
#             flash('Voter must be at least 18 years old!')
#             return redirect(url_for('register'))

#         # Check for existing username
#         conn = sqlite3.connect('voting_system.db')
#         c = conn.cursor()
#         c.execute("SELECT id FROM users WHERE username = ?", (username,))
#         if c.fetchone():
#             conn.close()
#             flash('Username already registered!')
#             return redirect(url_for('register'))
#         conn.close()

#         # Register user
#         private_key, public_key = generate_key_pair()
#         certificate = issue_certificate(public_key, username)
#         register_user(full_name, username, password, dob, email, voter_id, private_key, public_key, certificate)
#         flash('Registration successful! Please log in.')
#         return redirect(url_for('login'))
#     return render_template('register.html')

# @app.route('/login', methods=['GET', 'POST'])
# def login():
#     if request.method == 'POST':
#         username = request.form['username']
#         password = request.form['password']
#         user = authenticate_user(username, password)
#         if user:
#             session['user_id'] = user['id']
#             flash('Login successful!')
#             return redirect(url_for('home'))
#         flash('Invalid credentials!')
#         return redirect(url_for('login'))
#     return render_template('login.html')

# @app.route('/vote', methods=['GET', 'POST'])
# def vote():
#     print(f"Session: {session}")  # Debug: Check session state
#     if 'user_id' not in session:
#         flash('Please log in to vote!')
#         return redirect(url_for('login'))

#     # Check if user has already voted
#     if has_voted(session['user_id']):
#         flash('You have already cast your vote!')
#         return redirect(url_for('home'))  # Redirect to home instead of tally

#     if request.method == 'POST':
#         selected_candidates = request.form.getlist('candidate')
#         if len(selected_candidates) != 1:
#             flash('Please select exactly one candidate!')
#             return redirect(url_for('vote'))
        
#         candidate = selected_candidates[0]
#         user_id = session['user_id']
#         user = get_user_certificate(user_id)
#         private_key = serialization.load_pem_private_key(user['private_key'], password=None)
#         certificate = x509.load_pem_x509_certificate(user['certificate'])
#         signature = sign_data(candidate.encode(), private_key)
#         store_vote(user_id, candidate, signature, certificate)
#         flash('Vote cast successfully!')
#         return redirect(url_for('home'))  # Redirect to home after successful vote

#     return render_template('vote.html')  # Return template for GET requests

# @app.route('/tally')
# def tally():
#     tally = get_vote_tally()
#     current_time = datetime.now().strftime('%I:%M %p +0545 on %A, %B %d, %Y')  # Format: 09:09 PM +0545 on Saturday, July 05, 2025
#     return render_template('tally.html', tally=tally, current_time=current_time)

# @app.route('/verify_all')
# def verify_all():
#     if 'user_id' not in session:
#         flash('Please log in to verify votes!')
#         return redirect(url_for('login'))
#     votes = get_all_votes()
#     invalid_votes = []
#     for vote in votes:
#         certificate = x509.load_pem_x509_certificate(vote['certificate'])
#         public_key = certificate.public_key()
#         is_valid = verify_signature(vote['candidate'].encode(), vote['signature'], public_key)
#         if not is_valid:
#             invalid_votes.append(vote['candidate'])
#     if invalid_votes:
#         flash(f"Invalid votes detected for: {', '.join(invalid_votes)}")
#     else:
#         flash('All votes are valid!')
#     return redirect(url_for('tally'))

# @app.route('/verify_vote/<int:vote_id>')
# def verify_vote(vote_id):
#     if 'user_id' not in session:
#         flash('Please log in to verify votes!')
#         return redirect(url_for('login'))
#     votes = get_all_votes()
#     vote = next((v for v in votes if v['id'] == vote_id), None)
#     if not vote:
#         flash('Vote not found!')
#         return redirect(url_for('tally'))
#     certificate = x509.load_pem_x509_certificate(vote['certificate'])
#     public_key = certificate.public_key()
#     is_valid = verify_signature(vote['candidate'].encode(), vote['signature'], public_key)
#     flash(f"Vote for {vote['candidate']}: {'Valid' if is_valid else 'Invalid'}")
#     return redirect(url_for('tally'))  # Keep individual verify for completeness

# @app.route('/logout')
# def logout():
#     session.pop('user_id', None)
#     flash('Logged out successfully!')
#     return redirect(url_for('home'))

# if __name__ == '__main__':
#     app.run(debug=True)


# Verified certificate

# import os
# import sqlite3
# from flask import Flask, request, render_template, redirect, url_for, flash, session
# from cryptography.hazmat.primitives import serialization
# from cryptography import x509
# from cryptography.hazmat.primitives.asymmetric import padding
# from cryptography.hazmat.primitives import hashes
# from datetime import datetime, timedelta
# from crypto_utils import generate_key_pair, issue_certificate, sign_data, verify_signature
# from database import init_db, register_user, authenticate_user, store_vote, get_user_certificate, get_all_votes, has_voted, get_vote_tally

# app = Flask(__name__)
# app.secret_key = 'supersecretkey123'

# # Initialize database
# init_db()

# @app.route('/')
# def home():
#     return render_template('home.html', authenticated='user_id' in session)

# @app.route('/register', methods=['GET', 'POST'])
# def register():
#     if request.method == 'POST':
#         full_name = request.form['full_name']
#         username = request.form['username']
#         password = request.form['password']
#         confirm_password = request.form['confirm_password']
#         dob = request.form['dob']
#         email = request.form['email']
#         voter_id = request.form['voter_id']

#         # Validate password match
#         if password != confirm_password:
#             flash('Passwords do not match!')
#             return redirect(url_for('register'))

#         # Validate age (must be at least 18)
#         dob_date = datetime.strptime(dob, '%Y-%m-%d')
#         today = datetime.now()
#         age = today.year - dob_date.year - ((today.month, today.day) < (dob_date.month, dob_date.day))
#         if age < 18:
#             flash('Voter must be at least 18 years old!')
#             return redirect(url_for('register'))

#         # Check for existing username
#         conn = sqlite3.connect('voting_system.db')
#         c = conn.cursor()
#         c.execute("SELECT id FROM users WHERE username = ?", (username,))
#         if c.fetchone():
#             conn.close()
#             flash('Username already registered!')
#             return redirect(url_for('register'))
#         conn.close()

#         # Register user
#         private_key, public_key = generate_key_pair()
#         certificate = issue_certificate(public_key, username)
#         try:
#             register_user(full_name, username, password, dob, email, voter_id, private_key, public_key, certificate)
#             flash('Registration successful! Please log in.')
#             return redirect(url_for('login'))
#         except Exception as e:
#             flash(f'Registration failed: {str(e)}')
#             return redirect(url_for('register'))
#     return render_template('register.html')

# @app.route('/login', methods=['GET', 'POST'])
# def login():
#     if request.method == 'POST':
#         username = request.form['username']
#         password = request.form['password']
#         user = authenticate_user(username, password)
#         if user:
#             print(f"Authenticated user: {user}")  # Debug
#             user_data = get_user_certificate(user['id'])
#             print(f"User data from get_user_certificate: {user_data}")  # Debug
#             if not user_data or not user_data.get('private_key') or not user_data.get('certificate'):
#                 flash('User certificate or private key not found in database!')
#                 return redirect(url_for('login'))

#             session['user_id'] = user['id']
#             flash('Initial authentication successful! Verifying private key...')

#             challenge = os.urandom(32).hex()
#             session['challenge'] = challenge
#             print(f"Generated challenge: {challenge}")  # Debug

#             try:
#                 certificate = user_data['certificate']
#                 private_key = user_data['private_key']
#                 print(f"Certificate validity: {certificate.not_valid_before} to {certificate.not_valid_after}")  # Debug
#             except ValueError as e:
#                 flash(f'Error loading certificate or private key: {str(e)}')
#                 session.pop('user_id', None)
#                 return redirect(url_for('login'))

#             signature = sign_data(challenge.encode(), private_key)
#             public_key = certificate.public_key()
#             try:
#                 public_key.verify(
#                     signature,
#                     challenge.encode(),
#                     padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
#                     hashes.SHA256()
#                 )
#                 if certificate.not_valid_before <= datetime.now() <= certificate.not_valid_after:
#                     flash('Login successful with private key confirmation!')
#                     return redirect(url_for('home'))
#                 else:
#                     flash('Certificate is expired or not yet valid!')
#                     session.pop('user_id', None)
#             except Exception as e:
#                 flash(f'Invalid signature or certificate validation failed: {str(e)}')
#                 print(f"Verification error details: {str(e)}")  # Debug
#                 session.pop('user_id', None)
#         else:
#             flash('Invalid credentials!')
#         return redirect(url_for('login'))
#     return render_template('login.html')

# @app.route('/vote', methods=['GET', 'POST']) 
# def vote():
#     print(f"Session: {session}")  # Debug: Check session state
#     if 'user_id' not in session:
#         flash('Please log in to vote!')
#         return redirect(url_for('login'))

#     # Check if user has already voted
#     if has_voted(session['user_id']):
#         flash('You have already cast your vote!')
#         return redirect(url_for('home'))

#     if request.method == 'POST':
#         selected_candidates = request.form.getlist('candidate')
#         if len(selected_candidates) != 1:
#             flash('Please select exactly one candidate!')
#             return redirect(url_for('vote'))
        
#         candidate = selected_candidates[0]
#         user_id = session['user_id']
#         user = get_user_certificate(user_id)
#         if not user or not user.get('private_key') or not user.get('certificate'):
#             flash('User certificate or private key not found in database!')
#             return redirect(url_for('vote'))
#         try:
#             private_key = user['private_key']
#             certificate = user['certificate']
#             print(f"Signing data: {candidate.encode()}, with private_key type: {type(private_key)}")  # Debug
#             # Serialize private_key to PEM bytes
#             private_key_pem = private_key.private_bytes(
#                 encoding=serialization.Encoding.PEM,
#                 format=serialization.PrivateFormat.TraditionalOpenSSL,
#                 encryption_algorithm=serialization.NoEncryption()
#             )
#             signature = sign_data(private_key_pem, candidate.encode())  # Pass PEM bytes and data
#             store_vote(user_id, candidate, signature, certificate)
#             flash('Vote cast successfully!')
#             return redirect(url_for('home'))
#         except Exception as e:
#             flash(f'Error casting vote: {str(e)}')
#             print(f"Vote error details: {str(e)}")  # Debug
#             return redirect(url_for('vote'))

#     return render_template('vote.html')

# @app.route('/tally')
# def tally():
#     tally = get_vote_tally()
#     current_time = datetime.now().strftime('%I:%M %p +0545 on %A, %B %d, %Y')
#     return render_template('tally.html', tally=tally, current_time=current_time)

# @app.route('/verify_all')
# def verify_all():
#     if 'user_id' not in session:
#         flash('Please log in to verify votes!')
#         return redirect(url_for('login'))
#     votes = get_all_votes()
#     invalid_votes = []
#     for vote in votes:
#         try:
#             certificate = x509.load_pem_x509_certificate(vote['certificate'])
#             public_key = certificate.public_key()
#             is_valid = verify_signature(vote['candidate'].encode(), vote['signature'], public_key)
#             if not is_valid:
#                 invalid_votes.append(vote['candidate'])
#         except Exception as e:
#             invalid_votes.append(vote['candidate'])
#             print(f"Error verifying vote: {str(e)}")
#     if invalid_votes:
#         flash(f"Invalid votes detected for: {', '.join(invalid_votes)}")
#     else:
#         flash('All votes are valid!')
#     return redirect(url_for('tally'))

# @app.route('/verify_vote/<int:vote_id>')
# def verify_vote(vote_id):
#     if 'user_id' not in session:
#         flash('Please log in to verify votes!')
#         return redirect(url_for('login'))
#     votes = get_all_votes()
#     vote = next((v for v in votes if v['id'] == vote_id), None)
#     if not vote:
#         flash('Vote not found!')
#         return redirect(url_for('tally'))
#     try:
#         certificate = x509.load_pem_x509_certificate(vote['certificate'])
#         public_key = certificate.public_key()
#         is_valid = verify_signature(vote['candidate'].encode(), vote['signature'], public_key)
#         flash(f"Vote for {vote['candidate']}: {'Valid' if is_valid else 'Invalid'}")
#     except Exception as e:
#         flash(f"Error verifying vote: {str(e)}")
#     return redirect(url_for('tally'))

# @app.route('/logout')
# def logout():
#     session.pop('user_id', None)
#     session.pop('challenge', None)
#     flash('Logged out successfully!')
#     return redirect(url_for('home'))

# if __name__ == '__main__':
#     app.run(debug=True)


# main.py
import os
import sqlite3
from flask import Flask, request, render_template, redirect, url_for, flash, session # type: ignore
from cryptography.hazmat.primitives import serialization # type: ignore
from cryptography import x509 # type: ignore
from cryptography.hazmat.primitives.asymmetric import padding # type: ignore
from cryptography.hazmat.primitives import hashes # type: ignore
from datetime import datetime, timedelta
# Import all necessary functions from crypto_utils and database
from crypto_utils import generate_key_pair, issue_certificate, sign_data, verify_signature, decrypt_private_key, encrypt_private_key
from database import init_db, register_user, authenticate_user, store_vote, get_user_certificate, get_all_votes, has_voted, get_vote_tally

app = Flask(__name__)
app.secret_key = 'supersecretkey123'

# Initialize database
init_db()

@app.route('/')
def home():
    return render_template('home.html', authenticated='user_id' in session)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        full_name = request.form['full_name']
        username = request.form['username']
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        dob = request.form['dob']
        email = request.form['email']
        voter_id = request.form['voter_id']

        # Validate password match
        if password != confirm_password:
            flash('Passwords do not match!')
            return redirect(url_for('register'))

        # Validate age (must be at least 18)
        dob_date = datetime.strptime(dob, '%Y-%m-%d')
        today = datetime.now()
        age = today.year - dob_date.year - ((today.month, today.day) < (dob_date.month, dob_date.day))
        if age < 18:
            flash('Voter must be at least 18 years old!')
            return redirect(url_for('register'))

        # Check for existing username
        conn = sqlite3.connect('voting_system.db')
        c = conn.cursor()
        c.execute("SELECT id FROM users WHERE username = ?", (username,))
        if c.fetchone():
            conn.close()
            flash('Username already registered!')
            return redirect(url_for('register'))
        conn.close()

        try:
            # Generate key pair using the user's password for encryption
            encrypted_private_key_bundle, public_pem = generate_key_pair(password)
            
            # Issue certificate using the public key PEM
            certificate_pem = issue_certificate(public_pem, username)
            
            # Register user with the encrypted private key bundle and PEM formats
            register_user(full_name, username, password, dob, email, voter_id, 
                          encrypted_private_key_bundle, public_pem, certificate_pem)
            flash('Registration successful! Please log in.')
            return redirect(url_for('login'))
        except Exception as e:
            flash(f'Registration failed: {str(e)}')
            return redirect(url_for('register'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = authenticate_user(username, password)
        if user:
            # Password authenticated, now get certificate and decrypted private key
            user_data = get_user_certificate(user['id'], password) # Pass password for decryption
            
            if not user_data or not user_data.get('private_key') or not user_data.get('certificate'):
                flash('User certificate or private key not found in database or decryption failed! Please try again with correct password.')
                return redirect(url_for('login'))

            session['user_id'] = user['id']
            flash('Initial authentication successful! Verifying private key...')

            challenge = os.urandom(32).hex()
            session['challenge'] = challenge # Store challenge for potential future use if needed

            try:
                certificate = user_data['certificate']
                private_key = user_data['private_key'] # This is the decrypted RSAPrivateKey object

                # Sign the challenge with the decrypted private key
                signature = sign_data(challenge.encode(), private_key)
                
                # Verify the signature with the public key from the certificate
                public_key = certificate.public_key()
                public_key.verify(
                    signature,
                    challenge.encode(),
                    padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                    hashes.SHA256()
                )

                if certificate.not_valid_before <= datetime.utcnow() <= certificate.not_valid_after: # Use utcnow for comparison
                    flash('Login successful with private key confirmation!')
                    return redirect(url_for('home'))
                else:
                    flash('Certificate is expired or not yet valid!')
                    session.pop('user_id', None)
            except Exception as e:
                flash(f'Invalid signature or certificate validation failed: {str(e)}')
                session.pop('user_id', None)
        else:
            flash('Invalid credentials!')
        return redirect(url_for('login'))
    return render_template('login.html')

@app.route('/vote', methods=['GET', 'POST'])
def vote():
    if 'user_id' not in session:
        flash('Please log in to vote!')
        return redirect(url_for('login'))

    # Check if user has already voted
    if has_voted(session['user_id']):
        flash('You have already cast your vote!')
        return redirect(url_for('home'))

    if request.method == 'POST':
        selected_candidates = request.form.getlist('candidate')
        if len(selected_candidates) != 1:
            flash('Please select exactly one candidate!')
            return redirect(url_for('vote'))
        
        candidate = selected_candidates[0]
        user_id = session['user_id']
        password = request.form['password'] # Assume password is submitted with the vote form

        user_data = get_user_certificate(user_id, password) # Pass password for decryption
        if not user_data or not user_data.get('private_key') or not user_data.get('certificate'):
            flash('User certificate or private key not found or decryption failed! Please provide correct password.')
            return redirect(url_for('vote'))

        try:
            private_key = user_data['private_key'] # This is the decrypted RSAPrivateKey object
            certificate = user_data['certificate'] # This is the x509.Certificate object

            signature = sign_data(candidate.encode(), private_key)
            
            # Store vote with the signature and certificate PEM
            store_vote(user_id, candidate, signature, certificate.public_bytes(serialization.Encoding.PEM))
            flash('Vote cast successfully!')
            return redirect(url_for('home'))
        except Exception as e:
            flash(f'Error casting vote: {str(e)}')
            return redirect(url_for('vote'))

    return render_template('vote.html')

@app.route('/tally')
def tally():
    tally = get_vote_tally()
    current_time = datetime.now().strftime('%I:%M %p +0545 on %A, %B %d, %Y')
    return render_template('tally.html', tally=tally, current_time=current_time)

@app.route('/verify_all')
def verify_all():
    if 'user_id' not in session:
        flash('Please log in to verify votes!')
        return redirect(url_for('login'))
    votes = get_all_votes()
    invalid_votes = []
    for vote in votes:
        try:
            certificate = x509.load_pem_x509_certificate(vote['certificate']) # certificate is already PEM bytes
            public_key = certificate.public_key()
            is_valid = verify_signature(vote['candidate'].encode(), vote['signature'], public_key)
            if not is_valid:
                invalid_votes.append(vote['candidate'])
        except Exception as e:
            invalid_votes.append(vote['candidate'])
            print(f"Error verifying vote: {str(e)}") # Log the error for debugging
    if invalid_votes:
        flash(f"Invalid votes detected for: {', '.join(invalid_votes)}")
    else:
        flash('All votes are valid!')
    return redirect(url_for('tally'))

@app.route('/verify_vote/<int:vote_id>')
def verify_vote(vote_id):
    if 'user_id' not in session:
        flash('Please log in to verify votes!')
        return redirect(url_for('login'))
    votes = get_all_votes()
    vote = next((v for v in votes if v['id'] == vote_id), None)
    if not vote:
        flash('Vote not found!')
        return redirect(url_for('tally'))
    try:
        certificate = x509.load_pem_x509_certificate(vote['certificate'])
        public_key = certificate.public_key()
        is_valid = verify_signature(vote['candidate'].encode(), vote['signature'], public_key)
        flash(f"Vote for {vote['candidate']}: {'Valid' if is_valid else 'Invalid'}")
    except Exception as e:
        flash(f"Error verifying vote: {str(e)}")
    return redirect(url_for('tally'))

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    flash('Logged out successfully!')
    return redirect(url_for('home'))

if __name__ == '__main__':
    app.run(debug=True)