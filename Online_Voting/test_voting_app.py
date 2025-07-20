import unittest
import sqlite3
import os
from datetime import datetime, timedelta
from flask import Flask
from cryptography import x509
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from main import app
from crypto_utils import generate_key_pair, issue_certificate, sign_data, verify_signature, decrypt_private_key
from database import init_db, register_user, authenticate_user, store_vote, get_user_certificate, get_all_votes, has_voted, get_vote_tally

class VotingSystemTests(unittest.TestCase):
    def setUp(self):
        # Set up Flask test client
        self.app = app
        self.app.config['TESTING'] = True
        self.client = self.app.test_client()

        # Use in-memory SQLite database for testing
        self.app.config['DATABASE'] = ':memory:'
        init_db()  # Initialize the in-memory database

        # Test user data
        self.user1 = {
            'full_name': 'Test User 1',
            'username': 'testuser1',
            'password': 'securepassword1',
            'dob': '1990-01-01',
            'email': 'test1@example.com',
            'voter_id': 'VOTER001'
        }
        self.user2 = {
            'full_name': 'Test User 2',
            'username': 'testuser2',
            'password': 'securepassword2',
            'dob': '1995-02-02',
            'email': 'test2@example.com',
            'voter_id': 'VOTER002'
        }
        self.candidate = 'Balen Shah (Independent)'

    def tearDown(self):
        # Clean up database after each test
        conn = sqlite3.connect('voting_system.db')
        c = conn.cursor()
        c.execute('DROP TABLE IF EXISTS users')
        c.execute('DROP TABLE IF EXISTS votes')
        conn.commit()
        conn.close()

    def test_generate_key_pair(self):
        """Test key pair generation and encryption/decryption."""
        password = 'testpassword'
        encrypted_private_key_bundle, public_pem = generate_key_pair(password)
        self.assertIsNotNone(encrypted_private_key_bundle)
        self.assertIsNotNone(public_pem)
        self.assertTrue(public_pem.startswith(b'-----BEGIN PUBLIC KEY-----'))

        # Test decryption
        private_key = decrypt_private_key(encrypted_private_key_bundle, password)
        self.assertIsInstance(private_key, rsa.RSAPrivateKey)

        # Test decryption with wrong password
        with self.assertRaises(ValueError):
            decrypt_private_key(encrypted_private_key_bundle, 'wrongpassword')

    def test_issue_certificate(self):
        """Test certificate issuance."""
        _, public_pem = generate_key_pair('testpassword')
        certificate_pem = issue_certificate(public_pem, 'testuser1')
        self.assertIsNotNone(certificate_pem)
        certificate = x509.load_pem_x509_certificate(certificate_pem)
        self.assertEqual(certificate.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value, 'testuser1')
        self.assertTrue(certificate.not_valid_after > datetime.utcnow())

    def test_sign_and_verify_signature(self):
        """Test signing and verifying data."""
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        public_key = private_key.public_key()
        data = b"Test vote"
        signature = sign_data(data, private_key)
        self.assertTrue(verify_signature(data, signature, public_key))
        self.assertFalse(verify_signature(b"Wrong data", signature, public_key))

    def test_register_user(self):
        """Test user registration."""
        encrypted_private_key_bundle, public_pem = generate_key_pair(self.user1['password'])
        certificate_pem = issue_certificate(public_pem, self.user1['username'])
        register_user(
            self.user1['full_name'], self.user1['username'], self.user1['password'],
            self.user1['dob'], self.user1['email'], self.user1['voter_id'],
            encrypted_private_key_bundle, public_pem, certificate_pem
        )
        conn = sqlite3.connect('voting_system.db')
        c = conn.cursor()
        c.execute("SELECT username, full_name FROM users WHERE username = ?", (self.user1['username'],))
        user = c.fetchone()
        conn.close()
        self.assertIsNotNone(user)
        self.assertEqual(user[0], self.user1['username'])
        self.assertEqual(user[1], self.user1['full_name'])

    def test_authenticate_user(self):
        """Test user authentication."""
        encrypted_private_key_bundle, public_pem = generate_key_pair(self.user1['password'])
        certificate_pem = issue_certificate(public_pem, self.user1['username'])
        register_user(
            self.user1['full_name'], self.user1['username'], self.user1['password'],
            self.user1['dob'], self.user1['email'], self.user1['voter_id'],
            encrypted_private_key_bundle, public_pem, certificate_pem
        )
        user = authenticate_user(self.user1['username'], self.user1['password'])
        self.assertIsNotNone(user)
        self.assertEqual(user['username'], self.user1['username'])

        # Test wrong password
        user = authenticate_user(self.user1['username'], 'wrongpassword')
        self.assertIsNone(user)

    def test_vote_casting(self):
        """Test casting a vote."""
        # Register user
        encrypted_private_key_bundle, public_pem = generate_key_pair(self.user1['password'])
        certificate_pem = issue_certificate(public_pem, self.user1['username'])
        register_user(
            self.user1['full_name'], self.user1['username'], self.user1['password'],
            self.user1['dob'], self.user1['email'], self.user1['voter_id'],
            encrypted_private_key_bundle, public_pem, certificate_pem
        )
        user = authenticate_user(self.user1['username'], self.user1['password'])

        # Simulate login
        with self.client.session_transaction() as sess:
            sess['user_id'] = user['id']

        # Cast vote
        response = self.client.post('/vote', data={
            'candidate': self.candidate,
            'password': self.user1['password']
        }, follow_redirects=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'Vote cast successfully!', response.data)

        # Verify vote in database
        votes = get_all_votes()
        self.assertEqual(len(votes), 1)
        self.assertEqual(votes[0]['candidate'], self.candidate)

    def test_prevent_duplicate_votes(self):
        """Test that a user cannot vote twice."""
        # Register user
        encrypted_private_key_bundle, public_pem = generate_key_pair(self.user1['password'])
        certificate_pem = issue_certificate(public_pem, self.user1['username'])
        register_user(
            self.user1['full_name'], self.user1['username'], self.user1['password'],
            self.user1['dob'], self.user1['email'], self.user1['voter_id'],
            encrypted_private_key_bundle, public_pem, certificate_pem
        )
        user = authenticate_user(self.user1['username'], self.user1['password'])

        # Simulate login
        with self.client.session_transaction() as sess:
            sess['user_id'] = user['id']

        # Cast first vote
        self.client.post('/vote', data={
            'candidate': self.candidate,
            'password': self.user1['password']
        }, follow_redirects=True)

        # Attempt second vote
        response = self.client.post('/vote', data={
            'candidate': self.candidate,
            'password': self.user1['password']
        }, follow_redirects=True)
        self.assertIn(b'You have already cast your vote!', response.data)

    def test_unauthorized_access(self):
        """Test that unauthorized users cannot vote."""
        # Attempt to vote without logging in
        response = self.client.post('/vote', data={
            'candidate': self.candidate,
            'password': 'somepassword'
        }, follow_redirects=True)
        self.assertIn(b'Please log in to vote!', response.data)

    def test_certificate_spoofing(self):
        """Test protection against certificate spoofing."""
        # Register legitimate user
        encrypted_private_key_bundle, public_pem = generate_key_pair(self.user1['password'])
        certificate_pem = issue_certificate(public_pem, self.user1['username'])
        register_user(
            self.user1['full_name'], self.user1['username'], self.user1['password'],
            self.user1['dob'], self.user1['email'], self.user1['voter_id'],
            encrypted_private_key_bundle, public_pem, certificate_pem
        )
        user = authenticate_user(self.user1['username'], self.user1['password'])

        # Simulate login
        with self.client.session_transaction() as sess:
            sess['user_id'] = user['id']

        # Create a fake certificate with a different key pair
        fake_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        fake_public_key = fake_private_key.public_key()
        fake_public_pem = fake_public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        fake_certificate_pem = issue_certificate(fake_public_pem, 'fakeuser')

        # Attempt to vote with fake certificate
        user_data = get_user_certificate(user['id'], self.user1['password'])
        private_key = user_data['private_key']
        signature = sign_data(self.candidate.encode(), private_key)

        # Store vote with fake certificate
        store_vote(user['id'], self.candidate, signature, fake_certificate_pem)

        # Verify votes
        with self.client.session_transaction() as sess:
            sess['user_id'] = user['id']
        response = self.client.get('/verify_all', follow_redirects=True)
        self.assertIn(b'Invalid votes detected for: Balen Shah (Independent)', response.data)

    def test_man_in_the_middle_signature_tampering(self):
        """Test protection against signature tampering (man-in-the-middle attack)."""
        # Register user
        encrypted_private_key_bundle, public_pem = generate_key_pair(self.user1['password'])
        certificate_pem = issue_certificate(public_pem, self.user1['username'])
        register_user(
            self.user1['full_name'], self.user1['username'], self.user1['password'],
            self.user1['dob'], self.user1['email'], self.user1['voter_id'],
            encrypted_private_key_bundle, public_pem, certificate_pem
        )
        user = authenticate_user(self.user1['username'], self.user1['password'])

        # Simulate login
        with self.client.session_transaction() as sess:
            sess['user_id'] = user['id']

        # Cast legitimate vote
        user_data = get_user_certificate(user['id'], self.user1['password'])
        private_key = user_data['private_key']
        certificate = user_data['certificate']
        signature = sign_data(self.candidate.encode(), private_key)
        store_vote(user['id'], self.candidate, signature, certificate.public_bytes(serialization.Encoding.PEM))

        # Simulate MITM by tampering with the signature
        tampered_signature = signature[:-1] + bytes([signature[-1] ^ 1])  # Flip last bit
        store_vote(user['id'] + 1, self.candidate, tampered_signature, certificate.public_bytes(serialization.Encoding.PEM))

        # Verify votes
        response = self.client.get('/verify_all', follow_redirects=True)
        self.assertIn(b'Invalid votes detected for: Balen Shah (Independent)', response.data)

    def test_vote_tally(self):
        """Test vote tally accuracy."""
        # Register two users
        for user in [self.user1, self.user2]:
            encrypted_private_key_bundle, public_pem = generate_key_pair(user['password'])
            certificate_pem = issue_certificate(public_pem, user['username'])
            register_user(
                user['full_name'], user['username'], user['password'],
                user['dob'], user['email'], user['voter_id'],
                encrypted_private_key_bundle, public_pem, certificate_pem
            )

        # Cast votes
        users = [authenticate_user(self.user1['username'], self.user1['password']),
                 authenticate_user(self.user2['username'], self.user2['password'])]
        for i, user in enumerate(users):
            with self.client.session_transaction() as sess:
                sess['user_id'] = user['id']
            self.client.post('/vote', data={
                'candidate': self.candidate,
                'password': [self.user1['password'], self.user2['password']][i]
            }, follow_redirects=True)

        # Check tally
        tally = get_vote_tally()
        self.assertEqual(tally.get(self.candidate, 0), 2)

if __name__ == '__main__':
    unittest.main()