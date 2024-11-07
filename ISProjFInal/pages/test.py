import base64
import os
import smtplib
import qrcode
from typing import Final
import telebot
from Cryptodome.Cipher import PKCS1_OAEP, AES
from Cryptodome.Protocol.KDF import PBKDF2
from Cryptodome.PublicKey import RSA
from qreader import QReader
import cv2
from connect import getdb

# Initialize the bot
TOKEN: Final = '7812527416:AAHVU5DOCX2k_QQr-upg4QpsrGH0sqiCB-M'
BOT_USERNAME: Final = '@voiceauthisprojbot'
bot = telebot.TeleBot(TOKEN)

# Store active users and their states
active_users = set()
user_states = {}


def format_pem_key(key_bytes: bytes) -> str:
    """Format a key in PEM format"""
    return key_bytes.decode('utf-8')

def send_key(user, private_key_pem):
    server = smtplib.SMTP('smtp.gmail.com', 587)
    server.starttls()
    print("Starting SMTP server")
    server.login('isprojectmit2024@gmail.com', 'cbyn eoro gief jtof')
    print("Logged in to SMTP")
    server.sendmail('isprojectmit2024@gmail.com', user, private_key_pem)
    print("Mail sent")
    server.quit()

def encrypt_passphrase(passphrase):
    key = RSA.generate(1024)
    private_key = key.export_key()  # This gives us the PEM format directly
    public_key = key.publickey().export_key()
    cipher_rsa = PKCS1_OAEP.new(key.publickey())
    encrypted_passphrase = cipher_rsa.encrypt(passphrase.encode())

    # Format private key as PEM string
    private_key_pem = format_pem_key(private_key)
    print(f"Generated PEM private key: {private_key_pem}")
    return encrypted_passphrase, private_key_pem

def generate_qr(encrypted_passphrase):
    qr = qrcode.make(base64.b64encode(encrypted_passphrase).decode())
    qr.save("encrypted_passphrase_qr.png")
    print("QR code generated and saved as 'encrypted_passphrase_qr.png'")

def decrypt_data(encrypted_data):
    decoded = base64.b64decode(encrypted_data)
    secret_key: str = 'temp_secret_key'
    salt, nonce, tag, ciphertext = decoded[:16], decoded[16:32], decoded[32:48], decoded[48:]
    key = PBKDF2(secret_key.encode(), salt, dkLen=32)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    return cipher.decrypt_and_verify(ciphertext, tag).decode('utf-8')

def load_passphrase():
    db = getdb()
    dbphrase = db['phrases']
    latest_passphrase_data = dbphrase.find_one(sort=[('_id', -1)])
    if latest_passphrase_data:
        return decrypt_data(latest_passphrase_data['passphrase'])
    return None

@bot.message_handler(commands=['get'])
def get_command(message):
    user_id = message.from_user.id
    if user_id not in active_users:
        bot.reply_to(message, "Please start a session with /start first.")
        return

    # Extract private key from command
    try:
        # Get everything after the /get command
        key_text = message.text[len('/get '):].strip()

        if not key_text:
            bot.reply_to(message, "Please provide a private key after the command.")
            return

        # Verify PEM format and import key
        try:
            private_key = RSA.import_key(key_text)

            # Store the private key and set state to await photo
            user_states[user_id] = {
                'private_key': key_text,
                'awaiting_photo': True
            }
            bot.reply_to(message, "✅ Private key received! Now please send the QR code image to decrypt.")

        except ValueError:
            bot.reply_to(message, "❌ Invalid PEM format for private key. Please check the key format.")
        except Exception as e:
            bot.reply_to(message, f"❌ Error importing private key: {str(e)}")

    except Exception as e:
        bot.reply_to(message, f"An error occurred: {str(e)}")

@bot.message_handler(commands=['pass'])
def passphrase(message):
    user_id = message.from_user.id
    if user_id not in active_users:
        bot.reply_to(message, "Please start a session with /start first.")
        return

    username = message.text.split()[1] if len(message.text.split()) > 1 else None
    print(username)

    if not username:
        bot.reply_to(message, "Please provide a username to search for the associated email.")
        return

    # Retrieve email associated with the username from the database
    db = getdb()
    userdata = db['userdata']
    user_data = userdata.find_one({'username': username})

    if not user_data or 'email' not in user_data:
        bot.reply_to(message, f"No email found for username: {username}")
        return

    user_email = user_data['email']
    print(user_email)

    # Load the latest passphrase from the database
    passphrase = load_passphrase()
    if not passphrase:
        bot.reply_to(message, "No passphrase found in the database.")
        return

    # Encrypt the passphrase and get PEM private key
    encrypted_passphrase, private_key_pem = encrypt_passphrase(passphrase)

    # Generate QR code from the encrypted passphrase
    generate_qr(encrypted_passphrase)

    # Send the PEM private key via email
    send_key(user_email, private_key_pem)

    # Notify the user in the chat
    bot.reply_to(message,
                 f"✅ Passphrase encrypted and QR code generated. The private key has been sent to the email associated with {username}.")

@bot.message_handler(content_types=['photo'])
def handle_photo(message):
    user_id = message.from_user.id

    if user_id not in active_users:
        bot.reply_to(message, "Please start a session with /start first.")
        return

    if user_id not in user_states or not user_states[user_id].get('awaiting_photo'):
        bot.reply_to(message, "Please submit your private key first using the /get command.")
        return

    if not user_states[user_id].get('private_key'):
        bot.reply_to(message, "No private key found. Please use /get [private_key] first.")
        return

    print("Receiving image")
    try:
        # Download and save the photo
        file_info = bot.get_file(message.photo[-1].file_id)
        downloaded_file = bot.download_file(file_info.file_path)
        filename = f"qr_temp_{user_id}.png"

        with open(filename, 'wb') as f:
            f.write(downloaded_file)

        # Decode the QR
        qreader = QReader()
        image = cv2.imread(filename)
        decoded_text = qreader.detect_and_decode(image=image)

        if decoded_text[0]:
            encrypted_passphrase = base64.b64decode(decoded_text[0])
            private_key_pem = user_states[user_id]['private_key']

            try:
                # Import PEM key directly
                private_key = RSA.import_key(private_key_pem)
                cipher_rsa = PKCS1_OAEP.new(private_key)
                decrypted_passphrase = cipher_rsa.decrypt(encrypted_passphrase).decode('utf-8')
                bot.reply_to(message, f"🔓 Decrypted passphrase: {decrypted_passphrase}")
            except ValueError:
                bot.reply_to(message, "❌ Invalid PEM format in private key.")
            except Exception as e:
                bot.reply_to(message, f"❌ Decryption failed: {str(e)}")
        else:
            bot.reply_to(message,
                         "❌ Failed to decode QR code. Please ensure the image is clear and contains a valid QR code.")

        # Clean up
        if os.path.exists(filename):
            os.remove(filename)
            print(f"Temporary file {filename} deleted.")

        # Reset user state after processing
        user_states[user_id] = {
            'private_key': None,
            'awaiting_photo': False
        }

    except Exception as e:
        bot.reply_to(message, f"❌ An error occurred while processing the image: {str(e)}")
        if 'filename' in locals() and os.path.exists(filename):
            os.remove(filename)

@bot.message_handler(commands=['start'])
def start_command(message):
    user_id = message.from_user.id
    active_users.add(user_id)
    user_states[user_id] = {
        'private_key': None,
        'awaiting_photo': False
    }

    welcome_text = (
        "👋 Welcome to the Voice Authentication Bot!\n\n"
        "I can help you manage passphrases and QR codes securely.\n"
        "Use /help to see all available commands."
    )
    bot.reply_to(message, welcome_text)

@bot.message_handler(commands=['help'])
def help_command(message):
    help_text = (
        "🤖 Available Commands:\n\n"
        "/start - Start the bot and get welcome message\n"
        "/help - Show this help message\n"
        "/pass [username] - Generate encrypted QR code and send private key\n"
        "/get [private_key] - Start the decryption process\n"
        "/exit - End your session with the bot\n\n"
        "📸 For decryption:\n"
        "1. Use /get [private_key] to submit your private key\n"
        "2. Then send the QR code image to decrypt"
    )
    bot.reply_to(message, help_text)

@bot.message_handler(commands=['exit'])
def exit_command(message):
    user_id = message.from_user.id
    if user_id in active_users:
        active_users.remove(user_id)
        if user_id in user_states:
            del user_states[user_id]
        bot.reply_to(message, "👋 Goodbye! Your session has been ended. Use /start to begin a new session.")
    else:
        bot.reply_to(message, "You don't have an active session. Use /start to begin one.")

def main():
    while True:
        try:
            print("Starting bot...")
            bot.polling(none_stop=True)
        except Exception as e:
            print(f"An error occurred: {e}")
            import time
            time.sleep(5)


if __name__ == "__main__":
    main()