import base64
import random
import string
import streamlit as st
from Cryptodome.Cipher import AES
from Cryptodome.Protocol.KDF import PBKDF2
from Cryptodome.Random import get_random_bytes
from connect import getdb

st.success("Welcome to the Vault")
st.success("Ultimate Security")
db = getdb()
dbphrase = db['phrases']


def encrypt_data(data):
    salt = get_random_bytes(16)
    secret_key = "temp_secret_key"
    key = PBKDF2(secret_key.encode(), salt, dkLen=32)
    cipher = AES.new(key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(data.encode())
    return base64.b64encode(salt + cipher.nonce + tag + ciphertext).decode('utf-8')

def save_passphrase(passphrase):
    """
    Save encrypted passphrase to MongoDB
    """
    encrypted_passphrase = encrypt_data(passphrase)
    dbphrase.insert_one({"passphrase": encrypted_passphrase})

def update_passphrase():
    """
    Update passphrase and save to MongoDB
    """
    filename = "pages/wizardofoz.txt"
    with open(filename, 'r') as file:
        content = file.read()

        # Remove punctuation
        translator = str.maketrans('', '', string.punctuation)
        content = content.translate(translator)

        words = content.split()
        sentence = ' '.join(random.sample(words, 10))

    # Encrypt and save the passphrase in the database
    save_passphrase(sentence)
    return sentence

def clean_phrase_database():
    """
    Delete all passphrases in the database
    """
    try:
        # Delete all entries in the phrase database
        delete_result = dbphrase.delete_many({})

        if delete_result.deleted_count > 0:
            st.success("All passphrases have been deleted from the database.")
        else:
            st.warning("No passphrases were found in the database.")
    except Exception as e:
        st.error(f"An error occurred while cleaning the phrase database: {str(e)}")

clean_phrase_database()
update_passphrase()