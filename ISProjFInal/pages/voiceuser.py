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
from sklearn.metrics.pairwise import cosine_similarity
import speech_recognition as sr
from fuzzywuzzy import fuzz
from datetime import datetime
from Cryptodome.Cipher import AES
from Cryptodome.Protocol.KDF import PBKDF2
from connect import getdb
import random
import sounddevice as sd


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
                'timestamp': datetime.now().isoformat(),
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

class VoicePreprocessor:
    @staticmethod
    def preprocess_audio(input_file, output_file=None):
        """
        Comprehensive audio preprocessing method
        """
        try:
            # Read the audio file
            audio, sample_rate = sf.read(input_file)

            # Convert to mono if stereo
            if len(audio.shape) > 1:
                audio = audio.mean(axis=1)

            # Noise reduction
            reduced_noise = nr.reduce_noise(
                y=audio,
                sr=sample_rate,
                prop_decrease=0.8,
                n_std_thresh_stationary=1.5,
                stationary=True
            )

            # Normalize amplitude
            normalized_audio = librosa.util.normalize(reduced_noise)

            # Trim silence
            trimmed_audio, _ = librosa.effects.trim(
                normalized_audio,
                top_db=30
            )

            # Resample to standard rate
            target_sr = 16000
            resampled_audio = librosa.resample(
                trimmed_audio,
                orig_sr=sample_rate,
                target_sr=target_sr
            )

            # Save preprocessed file if output path provided
            if output_file:
                sf.write(output_file, resampled_audio, target_sr)

            return resampled_audio, target_sr

        except Exception as e:
            st.error(f"Audio preprocessing error: {e}")
            return None, None

class VoiceAuthenticator:
    def __init__(self, key):
        """
        Initialize voice authenticator with file-based storage
        """
        self.VOICE_RECORDINGS_DIR = 'user_voices_processed'
        self.USERS_DIR = 'user_data'
        self.SIMILARITY_THRESHOLD = 0.98
        self.salt = b'$B\xc2\xbcm\xb4F\xaa4\xd3\xd7\xc22\x07b\xa5'

        # Create necessary directories
        os.makedirs(self.VOICE_RECORDINGS_DIR, exist_ok=True)
        os.makedirs(self.USERS_DIR, exist_ok=True)
        self.logger = Logger()
        # Initialize current passphrase
        self.secret_key = key
        self.db = getdb()
        self.dbvoice = self.db['voice']
        self.dbphrase = self.db['phrases']


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

    def extract_mfcc(self, file_path):
        """
        Extract MFCC features from preprocessed audio file
        """
        try:
            preprocessed_audio, sr = VoicePreprocessor.preprocess_audio(file_path)

            if preprocessed_audio is None:
                return None

            # Extract MFCC features
            mfccs = librosa.feature.mfcc(
                y=preprocessed_audio,
                sr=sr,
                n_mfcc=20,
                n_fft=2048,
                hop_length=512
            )

            # Compute delta features
            delta_mfccs = librosa.feature.delta(mfccs)
            delta_delta_mfccs = librosa.feature.delta(mfccs, order=2)

            # Combine features
            combined_features = np.concatenate([
                np.mean(mfccs, axis=1),
                np.mean(delta_mfccs, axis=1),
                np.mean(delta_delta_mfccs, axis=1)
            ])

            return combined_features.tolist()

        except Exception as e:
            st.error(f"MFCC extraction error: {e}")
            return None

    def save_user_data(self, username, voice_embeddings):
        """
        Save encrypted username and voice embeddings to MongoDB
        """
        encrypted_username = username
        self.dbvoice.insert_one({
            "username": encrypted_username,
            "voice_embeddings": voice_embeddings
        })

    def load_user_data(self, username):
        """
        Load user voice embeddings from MongoDB
        """
        encrypted_username = username
        user_data = self.dbvoice.find_one({"username": encrypted_username})
        if user_data:
            return user_data['voice_embeddings']
        return None

    def register_user(self, username, audio_file):
        """
        Register a new user
        """
        try:
            # Create processed file path
            processed_file = os.path.join(
                self.VOICE_RECORDINGS_DIR,
                f"temp.wav"
            )

            # Preprocess the audio
            VoicePreprocessor.preprocess_audio(audio_file, processed_file)

            # Extract features
            voice_embeddings = self.extract_mfcc(processed_file)

            if voice_embeddings is not None:
                self.save_user_data(username, voice_embeddings)

                # Log successful registration
                self.logger.log_event(
                    'registration',
                    username,
                    {
                        'status': 'success',
                        'timestamp': datetime.now().isoformat(),
                        'embedding_size': len(voice_embeddings)
                    }
                )
                return True

                # Log failed registration
            self.logger.log_event(
                'registration',
                username,
                {
                    'status': 'failed',
                    'reason': 'Failed to extract voice embeddings',
                    'timestamp': datetime.now().isoformat()
                }
            )
            return False

        except Exception as e:
            # Log registration error
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

    def transcribe_audio(self, audio_path):
        """
        Convert audio to text
        """
        recognizer = sr.Recognizer()
        try:
            with sr.AudioFile(audio_path) as source:
                audio = recognizer.record(source)
                text = recognizer.recognize_google(audio)
                return text
        except Exception as e:
            st.error(f"Transcription error: {e}")
            return None

    def authenticate_user(self, username, audio_file):
        """
        Authenticate user with logging
        """
        processed_file = os.path.join(
            self.VOICE_RECORDINGS_DIR,
            f"temp2.wav"
        )
        VoicePreprocessor.preprocess_audio(audio_file, processed_file)

        input_mfcc = self.extract_mfcc(processed_file)
        if input_mfcc is None:
            self.logger.log_event(
                'authentication',
                username,
                {
                    'status': 'failed',
                    'reason': 'Failed to extract MFCC features',
                    'timestamp': datetime.now().isoformat()
                }
            )
            print("no mfcc")
            return False

        stored_embeddings = self.load_user_data(username)
        if stored_embeddings is None:
            self.logger.log_event(
                'authentication',
                username,
                {
                    'status': 'failed',
                    'reason': 'User not found',
                    'timestamp': datetime.now().isoformat()
                }
            )
            print("no embedding")
            return False

        input_mfcc_np = np.array(input_mfcc).reshape(1, -1)
        stored_mfcc_np = np.array(stored_embeddings).reshape(1, -1)
        sim_score = cosine_similarity(input_mfcc_np, stored_mfcc_np)[0][0]

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
            print("no transcription")
            return False
        print(self.load_passphrase().lower())
        print(transcribed_text)
        passphrase_match_score = fuzz.ratio(
            transcribed_text.lower(),
            self.load_passphrase().lower()
        )

        # Log authentication attempt details
        auth_details = {
            'status': 'success' if (sim_score >= self.SIMILARITY_THRESHOLD and
                                    passphrase_match_score >= 80) else 'failed',
            'voice_similarity_score': float(sim_score),
            'passphrase_match_score': passphrase_match_score,
            'transcribed_text': transcribed_text,
            'timestamp': datetime.now().isoformat()
        }

        self.logger.log_event('authentication', username, auth_details)

        return (sim_score >= self.SIMILARITY_THRESHOLD and
                passphrase_match_score >= 80)

    def save_passphrase(self, passphrase):
        """
        Save encrypted passphrase to MongoDB
        """
        encrypted_passphrase = self.encrypt_data(passphrase)
        self.dbphrase.insert_one({"passphrase": encrypted_passphrase})

    def load_passphrase(self):
        """
        Load and decrypt the most recent passphrase from MongoDB
        """
        latest_passphrase_data = self.dbphrase.find_one(sort=[('_id', -1)])
        if latest_passphrase_data:
            return self.decrypt_data(latest_passphrase_data['passphrase'])
        return None

    def update_passphrase(self):
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
        st.success(sentence)
        self.save_passphrase(sentence)
        return sentence

    def clean_phrase_database(self):
        """
        Keep only the most recent passphrase in the database
        """
        try:
            latest_phrase = self.dbphrase.find_one(sort=[('_id', -1)])

            if latest_phrase:
                # Delete all older passphrases except the latest one
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

def main():
    # Initialize authcount in session state to persist between reruns
    if 'authcount' not in st.session_state:
        st.session_state.authcount = 0

    st.title("Voice Authentication System")
    st.write("Secure authentication using voice recognition and passphrase verification")

    # Initialize authenticator
    authenticator = VoiceAuthenticator('temp_secret_key')

    # Sidebar for mode selection
    st.header("User Authentication")
    usernameauth = st.text_input("Enter username to authenticate")

    # QR Code Generation
    if st.button("Generate QR"):
        try:
            subprocess.run(["python", "pages/qr1.py"], check=True)
            st.switch_page("pages/qr1.py")
        except subprocess.CalledProcessError as e:
            st.error(f"Error generating QR code: {e}")

    # Show Sick Version button after 3 failed attempts
    if st.session_state.authcount >= 2:
        if st.button("Sick Version"):
            st.switch_page("pages/sick.py")

    # Audio Recording and Authentication
    if st.button("Record Audio for Authentication"):
        if not usernameauth:
            st.error("Please enter a username before authenticating")
            return

        try:
            st.session_state.authcount += 1
            record_audio()
            audio_file = 'temp_audio.wav'

            if not os.path.exists(audio_file):
                st.error("Audio recording failed")
                return

            authenticated_user = authenticator.authenticate_user(usernameauth, audio_file)

            # Log the authentication attempt
            authenticator.logger.log_event(
                'authentication',
                usernameauth,
                {
                    'status': 'success' if authenticated_user else 'failed',
                    'timestamp': datetime.now().isoformat(),
                    'attempt_number': st.session_state.authcount
                }
            )

            # Clean up the temporary audio file
            try:
                os.remove(audio_file)
            except OSError:
                pass

            if authenticated_user:
                st.success(f"User authenticated: {authenticated_user}")
                # Reset attempt counter on successful login
                st.session_state.authcount = 0
                st.switch_page("pages/vault.py")
            else:
                st.error(f"Authentication failed. Attempts: {st.session_state.authcount}")

        except Exception as e:
            st.error(f"Authentication error: {e}")
            authenticator.logger.log_event(
                'authentication_error',
                usernameauth,
                {
                    'status': 'error',
                    'timestamp': datetime.now().isoformat(),
                    'error': str(e)
                }
            )

if __name__ == "__main__":
    main()