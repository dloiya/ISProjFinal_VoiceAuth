import streamlit as st
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import os
import base64
from connect import getdb
import getmac


def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

def encrypt_password(password: str, key: bytes) -> tuple:
    nonce = os.urandom(12)
    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(password.encode()) + encryptor.finalize()
    return (base64.b64encode(nonce + ciphertext + encryptor.tag).decode(),
            base64.b64encode(key).decode())

def adduser():
    db = getdb()
    users_collection = db['userdata']
    st.title("Registration Page")
    new_username = st.text_input("New Username")
    new_password = st.text_input("New Password", type="password")
    email = st.text_input("Email")
    confirm_password = st.text_input("Confirm Password", type="password")

    if st.button("Register"):
        if new_password != confirm_password:
            st.error("Passwords do not match!")
            return

        if len(new_password) < 8:
            st.error("Password must be at least 12 characters long!")
            return

        # Check if username already exists
        if users_collection.find_one({"username": new_username}):
            st.error("Username already exists!")
            return

        salt = os.urandom(16)
        key = derive_key(new_password, salt)
        encrypted_password, key_b64 = encrypt_password(new_password, key)
        mac = encrypt_password(getmac.get_mac_address(), key)

        new_user = {
            "username": new_username,
            "password": encrypted_password,
            "salt": base64.b64encode(salt).decode(),
            "email": email,
            "mac": mac,
            "access": "user"
        }
        users_collection.insert_one(new_user)
        st.success("Registration successful!")
    if st.button("Back"):
        st.switch_page("pages/dashboard.py")

if __name__ == "__main__":
    adduser()