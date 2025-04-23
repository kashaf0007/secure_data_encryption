import streamlit as st
import json
import os
from hashlib import pbkdf2_hmac
from base64 import urlsafe_b64encode
from cryptography.fernet import Fernet
import time

# Constants
DATA_FILE = "data.json"
SALT = b"some_salt_value"
LOCKOUT_TIME = 60 

if "user" not in st.session_state:
    st.session_state.user = None
if "failed_attempts" not in st.session_state:
    st.session_state.failed_attempts = 0
if "lock_time" not in st.session_state:
    st.session_state.lock_time = 0
if "data" not in st.session_state:
    st.session_state.data = {}

# Load and Save Data
def load_data():
    if os.path.exists(DATA_FILE):
        with open(DATA_FILE, "r") as f:
            return json.load(f)
    return {}

def save_data():
    with open(DATA_FILE, "w") as f:
        json.dump(st.session_state.data, f)

# Hash and Key Generation
def hash_password(password):
    return pbkdf2_hmac("sha256", password.encode(), SALT, 100000).hex()

def generate_key(password):
    return urlsafe_b64encode(pbkdf2_hmac("sha256", password.encode(), SALT, 100000))

# Encrypt and Decrypt
def encrypt_data(text, password):
    cipher = Fernet(generate_key(password))
    return cipher.encrypt(text.encode()).decode()

def decrypt_data(token, password):
    try:
        cipher = Fernet(generate_key(password))
        return cipher.decrypt(token.encode()).decode()
    except:
        return None


st.session_state.data = load_data()

# UI
st.title("🔐 Easy Secure Data App")
menu = ["Login", "Sign Up", "Home", "Store Data", "Retrieve Data", "Logout"]
choice = st.sidebar.selectbox("Menu", menu)

if choice == "Login":
    st.subheader("🔑 Login")
    username = st.text_input("Username")
    password = st.text_input("Password", type="password")
    if st.button("Login"):
        user_data = st.session_state.data.get(username)
        if user_data:
            if st.session_state.failed_attempts >= 3 and time.time() - st.session_state.lock_time < LOCKOUT_TIME:
                st.error("⏳ Locked! Try again later.")
            elif user_data["password"] == hash_password(password):
                st.session_state.user = username
                st.session_state.failed_attempts = 0
                st.success("✅ Logged in!")
                st.experimental_rerun()
            else:
                st.session_state.failed_attempts += 1
                if st.session_state.failed_attempts >= 3:
                    st.session_state.lock_time = time.time()
                st.error("❌ Wrong password.")
        else:
            st.error("❌ User not found.")


elif choice == "Sign Up":
    st.subheader("📝 Sign Up")
    username = st.text_input("Create Username")
    password = st.text_input("Create Password", type="password")
    if st.button("Sign Up"):
        if username in st.session_state.data:
            st.error("⚠️ Username exists.")
        else:
            st.session_state.data[username] = {
                "password": hash_password(password),
                "data": []
            }
            save_data()
            st.success("✅ Account created!")


elif choice == "Home" and st.session_state.user:
    st.subheader(f"🏠 Welcome, {st.session_state.user}!")


elif choice == "Store Data" and st.session_state.user:
    st.subheader("📂 Store Encrypted Data")
    text = st.text_area("Enter text to encrypt")
    if st.button("Encrypt"):
        if text:
            encrypted = encrypt_data(text, st.session_state.user)
            st.session_state.data[st.session_state.user]["data"].append(encrypted)
            save_data()
            st.success("✅ Encrypted and saved!")
            st.code(encrypted)


elif choice == "Retrieve Data" and st.session_state.user:
    st.subheader("🔓 Decrypt Data")
    encrypted_text = st.text_area("Paste encrypted text")
    if st.button("Decrypt"):
        result = decrypt_data(encrypted_text, st.session_state.user)
        if result:
            st.success(f"✅ Decrypted: {result}")
        else:
            st.error("❌ Decryption failed.")

elif choice == "Logout":
    st.session_state.user = None
    st.success("✅ Logged out.")
    st.experimental_rerun()
