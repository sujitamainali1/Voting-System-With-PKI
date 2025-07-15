# # crypto_utils.py
# from cryptography.hazmat.primitives import serialization, hashes
# from cryptography.hazmat.primitives.asymmetric import rsa, padding
# from cryptography import x509
# from cryptography.x509.oid import NameOID
# from datetime import datetime, timedelta
# import os

# def generate_key_pair():
#     private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
#     public_key = private_key.public_key()
#     private_pem = private_key.private_bytes(
#         encoding=serialization.Encoding.PEM,
#         format=serialization.PrivateFormat.PKCS8,
#         encryption_algorithm=serialization.NoEncryption()
#     )
#     public_pem = public_key.public_bytes(
#         encoding=serialization.Encoding.PEM,
#         format=serialization.PublicFormat.SubjectPublicKeyInfo
#     )
#     return private_pem, public_pem

# def issue_certificate(public_key, username):
#     public_key = serialization.load_pem_public_key(public_key)
#     ca_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
#     subject = issuer = x509.Name([
#         x509.NameAttribute(NameOID.COMMON_NAME, f"{username}"),
#         x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Online Voting System"),
#     ])
#     cert = x509.CertificateBuilder().subject_name(subject).issuer_name(issuer).public_key(public_key).serial_number(
#         x509.random_serial_number()).not_valid_before(datetime.utcnow()).not_valid_after(
#         datetime.utcnow() + timedelta(days=365)).add_extension(
#         x509.SubjectAlternativeName([x509.DNSName("localhost")]), critical=False).sign(ca_private_key, hashes.SHA256())
#     return cert.public_bytes(serialization.Encoding.PEM)

# def sign_data(data, private_key):
#     # Use the private_key directly as an RSAPrivateKey object
#     signature = private_key.sign(
#         data,
#         padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
#         hashes.SHA256()
#     )
#     return signature

# def verify_signature(data, signature, public_key):
#     try:
#         public_key.verify(signature, data, padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())
#         return True
#     except:
#         return False


# crypto_utils.py
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import padding as symmetric_padding # Alias for symmetric padding
from cryptography.hazmat.primitives.asymmetric import padding as asymmetric_padding # Alias for asymmetric padding
from cryptography import x509
from cryptography.x509.oid import NameOID
from datetime import datetime, timedelta
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend

def _derive_key(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(password.encode()) # Ensure password is bytes

def encrypt_private_key(private_key_pem, password):
    salt = os.urandom(16)
    key = _derive_key(password, salt)
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    # PKCS7 padding for AES
    padder = symmetric_padding.PKCS7(algorithms.AES.block_size).padder() # Use symmetric_padding
    padded_data = padder.update(private_key_pem) + padder.finalize()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    return salt + iv + ciphertext # Bundle salt, iv, and ciphertext

def decrypt_private_key(encrypted_private_key_bundle, password):
    if not encrypted_private_key_bundle:
        raise ValueError("Encrypted private key bundle is empty.")
    
    salt = encrypted_private_key_bundle[:16]
    iv = encrypted_private_key_bundle[16:32]
    ciphertext = encrypted_private_key_bundle[32:]

    key = _derive_key(password, salt)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_data = decryptor.update(ciphertext) + decryptor.finalize()
    
    unpadder = symmetric_padding.PKCS7(algorithms.AES.block_size).unpadder() # Use symmetric_padding
    private_key_pem = unpadder.update(padded_data) + unpadder.finalize()
    
    return serialization.load_pem_private_key(private_key_pem, password=None)

def generate_key_pair(password):
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    
    encrypted_private_key_bundle = encrypt_private_key(private_pem, password)
    
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return encrypted_private_key_bundle, public_pem

def issue_certificate(public_key_pem, username):
    public_key = serialization.load_pem_public_key(public_key_pem)
    # Generate a new private key for the CA to sign the certificate
    # In a real system, this would be a persistent CA key
    ca_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, f"{username}"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Online Voting System"),
    ])
    
    cert = x509.CertificateBuilder().subject_name(subject).issuer_name(issuer).public_key(public_key).serial_number(
        x509.random_serial_number()
    ).not_valid_before(datetime.utcnow()).not_valid_after(
        datetime.utcnow() + timedelta(days=365)
    ).add_extension(
        x509.SubjectAlternativeName([x509.DNSName("localhost")]), critical=False
    ).sign(ca_private_key, hashes.SHA256())
    
    return cert.public_bytes(serialization.Encoding.PEM)

def sign_data(data, private_key): # private_key is now an RSAPrivateKey object
    signature = private_key.sign(
        data,
        asymmetric_padding.PSS(mgf=asymmetric_padding.MGF1(hashes.SHA256()), salt_length=asymmetric_padding.PSS.MAX_LENGTH), # Use asymmetric_padding
        hashes.SHA256()
    )
    return signature

def verify_signature(data, signature, public_key):
    try:
        public_key.verify(
            signature,
            data,
            asymmetric_padding.PSS(mgf=asymmetric_padding.MGF1(hashes.SHA256()), salt_length=asymmetric_padding.PSS.MAX_LENGTH), # Use asymmetric_padding
            hashes.SHA256()
        )
        return True
    except Exception: # Catch broader exceptions for robustness
        return False