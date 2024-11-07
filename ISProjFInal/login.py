import os
import json
import uuid
import datetime
import streamlit as st
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
from pages.connect import getdb
from getmac import get_mac_address

class Logger:
    def __init__(self):
        self.LOG_DIR = 'logs'
        self.LOG_FILE = os.path.join(self.LOG_DIR, 'auth_logs.json')

        # Create logs directory if it doesn't exist
        os.makedirs(self.LOG_DIR, exist_ok=True)

        # Create log file if it doesn't exist
        if not os.path.exists(self.LOG_FILE):
            with open(self.LOG_FILE, 'w') as f:
                json.dump([], f)

    def log_event(self, event_type, username, details):
        """
        Log an event with timestamp and unique ID
        """
        try:
            # Read existing logs
            with open(self.LOG_FILE, 'r') as f:
                logs = json.load(f)

            # Create new log entry
            log_entry = {
                'id': str(uuid.uuid4()),
                'timestamp': datetime.datetime.now().isoformat(),
                'event_type': event_type,
                'username': username,
                'details': details
            }

            # Add new entry
            logs.append(log_entry)

            # Write updated logs
            with open(self.LOG_FILE, 'w') as f:
                json.dump(logs, f, indent=2)

        except Exception as e:
            st.error(f"Logging error: {e}")


def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

def decrypt_password(encrypted_data: str, key: bytes) -> str:
    try:
        decoded = base64.b64decode(encrypted_data)
        nonce, ciphertext, tag = decoded[:12], decoded[12:-16], decoded[-16:]
        cipher = Cipher(algorithms.AES(key), modes.GCM(nonce, tag), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted = decryptor.update(ciphertext) + decryptor.finalize()
        return decrypted.decode()
    except (ValueError, KeyError):
        return None

def check_active_hours():
    current_time = datetime.datetime.now().time()
    start_time = datetime.time(9, 0)
    end_time = datetime.time(17, 0)
    return start_time <= current_time <= end_time

def login():
    st.title("Login Page")
    username = st.text_input("Username")
    password = st.text_input("Password", type="password")
    db = getdb()
    users_collection = db["userdata"]

    if st.button("Login"):
        user_data = users_collection.find_one({"username": username})

        if user_data:
            # Apply active hours check for admins only
            if user_data.get("role") == "admin" and not check_active_hours():
                st.error("Admin login is only allowed between 9 AM and 5 PM.")
                return False

            # Check if an admin is already logged in
            if user_data.get("role") == "admin":
                active_admin = users_collection.find_one({"is_active": True, "role": "admin"})
                if active_admin:
                    st.error("An admin is already logged in.")
                    return False

            stored_password = user_data["password"]
            salt = base64.b64decode(user_data["salt"])

            derived_key = derive_key(password, salt)
            decrypted_password = decrypt_password(stored_password, derived_key)

            if decrypted_password == password:
                # Additional check for admins' MAC address
                if user_data.get("role") == "admin":
                    stored_mac = user_data.get("mac_address")
                    current_mac = get_mac_address()

                    if stored_mac and stored_mac != current_mac:
                        st.error("Access denied: Unauthorized device.")
                        return False

                # Mark user as active in the database
                users_collection.update_one(
                    {"username": username},
                    {"$set": {"is_active": True}}
                )
                st.success("Login successful!")
                st.session_state.user = user_data
                return True
            else:
                st.error("Invalid username or password.")
        else:
            st.error("Invalid username or password.")
        return False

def logout():
    if "user" in st.session_state:
        db = getdb()
        users_collection = db["userdata"]
        users_collection.update_one(
            {"username": st.session_state.user["username"]},
            {"$set": {"is_active": False}}
        )
        del st.session_state.user
        st.info("You have been logged out.")

if __name__ == "__main__":
    if login():
        st.switch_page("pages/dashboard.py")
