import base64
import string
import subprocess
import streamlit as st
import os
import json
import uuid
import numpy as np
import librosa
import soundfile as sf
import noisereduce as nr
from datetime import datetime
from Cryptodome.Cipher import AES
from Cryptodome.Protocol.KDF import PBKDF2
from connect import getdb
import random
import sounddevice as sd
import speech_recognition as sr
from fuzzywuzzy import fuzz
from speechbrain.pretrained import SpeakerRecognition
from bson import Binary
import io


# [Previous Logger and VoicePreprocessor classes remain the same as in the last artifact]
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


class VoicePreprocessor:
    @staticmethod
    def preprocess_audio(input_file, output_file=None):
        try:
            audio, sample_rate = sf.read(input_file)
            if len(audio.shape) > 1:
                audio = audio.mean(axis=1)

            target_sr = 16000
            resampled_audio = librosa.resample(
                audio,
                orig_sr=sample_rate,
                target_sr=target_sr
            )

            reduced_noise = nr.reduce_noise(
                y=resampled_audio,
                sr=target_sr,
                prop_decrease=0.8,
                n_std_thresh_stationary=1.5,
                stationary=True
            )

            processed_audio = librosa.util.normalize(reduced_noise)

            if output_file:
                sf.write(output_file, processed_audio, target_sr)

            return audio, target_sr
        except Exception as e:
            return None, None


class VoiceAuthenticator:
    def __init__(self, key):
        self.VOICE_RECORDINGS_DIR = '../user_voices_processed'
        self.USERS_DIR = '../user_data'
        self.VERIFICATION_THRESHOLD = 0.75
        self.salt = b'$B\xc2\xbcm\xb4F\xaa4\xd3\xd7\xc22\x07b\xa5'

        os.makedirs(self.VOICE_RECORDINGS_DIR, exist_ok=True)
        os.makedirs(self.USERS_DIR, exist_ok=True)
        self.logger = Logger()
        self.secret_key = key
        self.db = getdb()
        self.dbvoice = self.db['voice2']
        self.dbphrase = self.db['phrases']

        self.speaker_model = SpeakerRecognition.from_hparams(
            source="speechbrain/spkrec-ecapa-voxceleb"
        )

    # [Previous VoiceAuthenticator methods remain the same as in the last artifact]
    def encrypt_data(self, data):
        salt = self.salt
        key = PBKDF2(self.secret_key.encode(), salt, dkLen=32)
        cipher = AES.new(key, AES.MODE_GCM)
        ciphertext, tag = cipher.encrypt_and_digest(data.encode())
        return base64.b64encode(salt + cipher.nonce + tag + ciphertext).decode('utf-8')

    def decrypt_data(self, encrypted_data):
        decoded = base64.b64decode(encrypted_data)
        salt, nonce, tag, ciphertext = decoded[:16], decoded[16:32], decoded[32:48], decoded[48:]
        key = PBKDF2(self.secret_key.encode(), salt, dkLen=32)
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        return cipher.decrypt_and_verify(ciphertext, tag).decode('utf-8')

    def save_user_data(self, username, audio_data):
        encrypted_username = username
        audio_binary = Binary(audio_data)
        self.dbvoice.insert_one({
            "username": encrypted_username,
            "voice_audio": audio_binary
        })

    def load_user_data(self, username):
        encrypted_username = username
        user_data = self.dbvoice.find_one({"username": encrypted_username})
        if user_data:
            return user_data['voice_audio']
        return None

    def register_user(self, username, audio_file):
        try:
            processed_file = os.path.join(
                self.VOICE_RECORDINGS_DIR,
                f"temp.wav"
            )

            VoicePreprocessor.preprocess_audio(audio_file, processed_file)

            with open(processed_file, 'rb') as f:
                audio_data = f.read()

            self.save_user_data(username, audio_data)

            self.logger.log_event(
                'registration',
                username,
                {
                    'status': 'success',
                    'timestamp': datetime.now().isoformat()
                }
            )
            return True

        except Exception as e:
            self.logger.log_event(
                'registration',
                username,
                {
                    'status': 'error',
                    'error_message': str(e),
                    'timestamp': datetime.now().isoformat()
                }
            )
            st.error(f"Registration error: {e}")
            return False

    def authenticate_user(self, username, audio_file):
        try:
            processed_file = os.path.join(
                self.VOICE_RECORDINGS_DIR,
                f"temp2.wav"
            )
            VoicePreprocessor.preprocess_audio(audio_file, processed_file)

            stored_audio = self.load_user_data(username)
            if stored_audio is None:
                self.logger.log_event(
                    'authentication',
                    username,
                    {
                        'status': 'failed',
                        'reason': 'User not found',
                        'timestamp': datetime.now().isoformat()
                    }
                )
                return False

            stored_file = os.path.join(
                self.VOICE_RECORDINGS_DIR,
                f"stored_temp.wav"
            )
            with open(stored_file, 'wb') as f:
                f.write(stored_audio)

            score, prediction = self.speaker_model.verify_files(processed_file, stored_file)

            transcribed_text = self.transcribe_audio(processed_file)
            if not transcribed_text:
                self.logger.log_event(
                    'authentication',
                    username,
                    {
                        'status': 'failed',
                        'reason': 'Failed to transcribe audio',
                        'timestamp': datetime.now().isoformat()
                    }
                )
                return False

            passphrase_match_score = fuzz.ratio(
                transcribed_text.lower(),
                self.load_passphrase().lower()
            )

            auth_details = {
                'status': 'success' if (score >= self.VERIFICATION_THRESHOLD and
                                        passphrase_match_score >= 80) else 'failed',
                'voice_similarity_score': float(score),
                'passphrase_match_score': passphrase_match_score,
                'transcribed_text': transcribed_text,
                'timestamp': datetime.now().isoformat()
            }

            self.logger.log_event('authentication', username, auth_details)

            os.remove(processed_file)
            os.remove(stored_file)

            return (score >= self.VERIFICATION_THRESHOLD and
                    passphrase_match_score >= 80)

        except Exception as e:
            self.logger.log_event(
                'authentication_error',
                username,
                {
                    'status': 'error',
                    'error_message': str(e),
                    'timestamp': datetime.now().isoformat()
                }
            )
            st.error(f"Authentication error: {e}")
            return False

    def transcribe_audio(self, audio_path):
        recognizer = sr.Recognizer()
        try:
            with sr.AudioFile(audio_path) as source:
                audio = recognizer.record(source)
                text = recognizer.recognize_google(audio)
                return text
        except Exception as e:
            st.error(f"Transcription error: {e}")
            return None

    def save_passphrase(self, passphrase):
        encrypted_passphrase = self.encrypt_data(passphrase)
        self.dbphrase.insert_one({"passphrase": encrypted_passphrase})

    def load_passphrase(self):
        latest_passphrase_data = self.dbphrase.find_one(sort=[('_id', -1)])
        if latest_passphrase_data:
            return self.decrypt_data(latest_passphrase_data['passphrase'])
        return None

    def update_passphrase(self):
        filename = "wizardofoz.txt"
        with open(filename, 'r') as file:
            content = file.read()
            translator = str.maketrans('', '', string.punctuation)
            content = content.translate(translator)
            words = content.split()
            sentence = ' '.join(random.sample(words, 10))
        st.success(f"New passphrase generated: {sentence}")
        self.save_passphrase(sentence)
        return sentence

    def clean_phrase_database(self):
        try:
            latest_phrase = self.dbphrase.find_one(sort=[('_id', -1)])
            if latest_phrase:
                self.dbphrase.delete_many({'_id': {'$ne': latest_phrase['_id']}})
                st.success("Phrase database cleaned. Only the most recent passphrase retained.")
            else:
                st.warning("No passphrases found in the database.")
        except Exception as e:
            st.error(f"An error occurred while cleaning the phrase database: {str(e)}")


def record_audio(duration=8, sample_rate=16000, filename="temp_audio.wav"):
    st.write("Recording...")
    audio_data = sd.rec(int(duration * sample_rate), samplerate=sample_rate, channels=1, dtype='float32')
    sd.wait()
    st.write("Recording complete!")
    # Save the audio data to a WAV file
    sf.write(filename, audio_data, sample_rate)
    st.audio("temp_audio.wav")
    print(filename)
    return filename

def main():
    st.set_page_config(
        page_title="Voice Authentication System",
        page_icon="🎙️",
        layout="wide"
    )

    # Initialize session state
    if 'authcount' not in st.session_state:
        st.session_state.authcount = 0
    if 'current_passphrase' not in st.session_state:
        st.session_state.current_passphrase = None

    st.title("🎙️ Advanced Voice Authentication System")
    st.write("Secure authentication using AI-powered voice recognition and passphrase verification")

    # Initialize authenticator
    authenticator = VoiceAuthenticator('temp_secret_key')

    # Create tabs for different functionalities
    username_reg = st.text_input("Enter username for registration", key="reg_username")
    st.header("User Registration")

    if st.button("Register New User"):
        if not username_reg:
            st.error("Please enter a username for registration")
        else:
            current_passphrase = authenticator.load_passphrase()
            if not current_passphrase:
                st.error("No passphrase found. Please generate one in the Admin tab first.")
            else:
                #st.info(f"Please record yourself saying: {current_passphrase}")
                audio_file = record_audio()

                if audio_file and os.path.exists(audio_file):
                    try:
                        with st.spinner("Registering user..."):
                            registered = authenticator.register_user(username_reg, audio_file)
                            if registered:
                                st.success(f"User {username_reg} registered successfully!")
                            else:
                                st.error(f"User registration failed for {username_reg}")

                        # Cleanup
                        try:
                            os.remove(audio_file)
                        except OSError:
                            pass
                    except Exception as e:
                        st.error(f"Registration error: {str(e)}")
                else:
                    st.error("Audio recording failed")


main()
