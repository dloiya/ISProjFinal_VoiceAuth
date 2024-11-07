import smtplib
import streamlit as st
from Cryptodome.Cipher import AES
from Cryptodome.Protocol.KDF import PBKDF2
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
from connect import getdb
import getmac
import os
import json
import uuid
from datetime import datetime, timedelta
import random
import string


# Logger class for logging events
class Logger:
    def __init__(self):
        self.LOG_DIR = '../logs'
        self.LOG_FILE = os.path.join(self.LOG_DIR, 'auth_logs.json')
        os.makedirs(self.LOG_DIR, exist_ok=True)
        if not os.path.exists(self.LOG_FILE):
            with open(self.LOG_FILE, 'w') as f:
                json.dump([], f)

    def log_event(self, event_type, username, details):
        try:
            with open(self.LOG_FILE, 'r') as f:
                logs = json.load(f)
            log_entry = {
                'id': str(uuid.uuid4()),
                'timestamp': datetime.now().isoformat(),
                'event_type': event_type,
                'username': username,
                'details': details
            }
            logs.append(log_entry)
            with open(self.LOG_FILE, 'w') as f:
                json.dump(logs, f, indent=2)
        except Exception as e:
            st.error(f"Logging error: {e}")

# OTP functions
def generate_otp():
    """Generate a 6-digit OTP"""
    return ''.join(random.choices(string.digits, k=6))

def send_otp(email, otp):
    """Send OTP via email"""
    try:
        server = smtplib.SMTP('smtp.gmail.com', 587)
        server.starttls()
        server.login('isprojectmit2024@gmail.com', 'cbyn eoro gief jtof')
        message = f"""Subject: Login Verification OTP

Your OTP for login verification is: {otp}

This OTP will expire in 5 minutes.
Do not share this OTP with anyone."""
        server.sendmail('isprojectmit2024@gmail.com', email, message)
        server.quit()
        return True
    except Exception as e:
        st.error(f"Error sending OTP: {e}")
        return False

def verify_otp_expiry(otp_time):
    """Check if OTP is within 5 minutes window"""
    if not otp_time:
        return False
    expiry_time = otp_time + timedelta(minutes=5)
    return datetime.now() < expiry_time

# Functions for password and passphrase handling
def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

def encrypt_data(data: str, key: bytes) -> str:
    nonce = os.urandom(12)
    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(data.encode()) + encryptor.finalize()
    return base64.b64encode(nonce + ciphertext + encryptor.tag).decode()

def decrypt_password(encrypted_data: str, key: bytes) -> str:
    try:
        decoded = base64.b64decode(encrypted_data)
        nonce, ciphertext, tag = decoded[:12], decoded[12:-16], decoded[-16:]
        cipher = Cipher(algorithms.AES(key), modes.GCM(nonce, tag), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted = decryptor.update(ciphertext) + decryptor.finalize()
        return decrypted.decode()
    except (ValueError, KeyError) as e:
        return None

def load_passphrase():
    db = getdb()
    dbphrase = db['phrases']
    latest_passphrase_data = dbphrase.find_one(sort=[('_id', -1)])
    if latest_passphrase_data:
        return decrypt_data(latest_passphrase_data['passphrase'])
    return None

def decrypt_data(encrypted_data):
    decoded = base64.b64decode(encrypted_data)
    secret_key: str = 'temp_secret_key'
    salt, nonce, tag, ciphertext = decoded[:16], decoded[16:32], decoded[32:48], decoded[48:]
    key = PBKDF2(secret_key.encode(), salt, dkLen=32)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    return cipher.decrypt_and_verify(ciphertext, tag).decode('utf-8')

def login():
    st.title("Sick Page")

    # Collect all credentials at once
    with st.form("login_form"):
        username = st.text_input("Username")
        password = st.text_input("Password", type="password")
        passphrase = st.text_input("Vault Passphrase", type="password")
        submit_button = st.form_submit_button("Request OTP")

    db = getdb()
    users_collection = db["userdata"]
    logger = Logger()

    # First stage - validate initial credentials and send OTP
    if submit_button and username and password and passphrase:
        user_data = users_collection.find_one({"username": username})

        if user_data:
            stored_password = user_data["password"]
            salt = base64.b64decode(user_data["salt"])
            stored_mac = user_data["mac"]

            # Verify MAC address
            derived_key = derive_key(password, salt)
            decrypted_password = decrypt_password(stored_password, derived_key)
            decrypted_mac = decrypt_password(stored_mac[0], derived_key)
            current_mac = getmac.get_mac_address()

            if decrypted_mac != current_mac:
                logger.log_event(
                    "login_failed",
                    username,
                    {"reason": "MAC address mismatch", "stored_mac": decrypted_mac, "current_mac": current_mac}
                )
                st.error("Device not recognized. Please contact support.")
                return False

            # Verify password
            if decrypted_password == password:
                # Verify passphrase
                stored_phrase = load_passphrase()
                if passphrase != stored_phrase:
                    logger.log_event(
                        "login_failed",
                        username,
                        {"reason": "Invalid passphrase", "attempt_time": datetime.now().isoformat()}
                    )
                    st.error("Invalid passphrase. Please try again.")
                    return False

                # Generate and send OTP
                otp = generate_otp()
                st.session_state.otp = otp
                st.session_state.otp_time = datetime.now()
                st.session_state.credentials_verified = True
                st.session_state.user_data = user_data

                if send_otp(user_data["email"], otp):
                    st.info(f"OTP has been sent to {user_data['email']}. Valid for 5 minutes.")
                else:
                    st.error("Failed to send OTP. Please try again.")
                    return False
            else:
                logger.log_event(
                    "login_failed",
                    username,
                    {"reason": "Invalid password", "attempt_time": datetime.now().isoformat()}
                )
                st.error("Invalid credentials.")
                return False
        else:
            logger.log_event(
                "login_failed",
                username,
                {"reason": "User not found", "attempt_time": datetime.now().isoformat()}
            )
            st.error("Invalid credentials.")
            return False

    # Second stage - verify OTP
    if st.session_state.get('credentials_verified'):
        with st.form("otp_form"):
            user_otp = st.text_input("Enter OTP")
            verify_otp_button = st.form_submit_button("Verify OTP")

        if verify_otp_button and user_otp:
            if not verify_otp_expiry(st.session_state.get('otp_time')):
                logger.log_event(
                    "login_failed",
                    username,
                    {"reason": "OTP expired", "attempt_time": datetime.now().isoformat()}
                )
                st.error("OTP has expired. Please try again.")
                del st.session_state.otp
                del st.session_state.otp_time
                del st.session_state.credentials_verified
                return False

            if user_otp == st.session_state.otp:
                user_data = st.session_state.user_data
                current_mac = getmac.get_mac_address()

                logger.log_event(
                    "login_successful",
                    user_data["username"],
                    {"timestamp": datetime.now().isoformat(), "mac_address": current_mac}
                )

                st.success("Login successful!")
                st.session_state.user = {
                    "username": user_data["username"],
                    "email": user_data["email"],
                    "access": user_data["access"],
                    "login_time": datetime.now().isoformat()
                }
                return True
            else:
                logger.log_event(
                    "login_failed",
                    username,
                    {"reason": "Invalid OTP", "attempt_time": datetime.now().isoformat()}
                )
                st.error("Invalid OTP. Please try again.")
                return False

    if st.button("Back"):
        st.switch_page("pages/voiceuser.py")

if __name__ == "__main__":
    if login():
        st.switch_page("pages/vault.py")
