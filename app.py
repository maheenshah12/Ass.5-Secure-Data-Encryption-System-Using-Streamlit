import streamlit as st
import json
import os
import hashlib
import time
from datetime import datetime, timedelta
from cryptography.fernet import Fernet
from base64 import urlsafe_b64encode


def get_cipher_key():
    password = b"super_secret_master_password" 
    salt = b"static_salt_value"
    key = hashlib.pbkdf2_hmac('sha256', password, salt, 100000)
    return Fernet(urlsafe_b64encode(key))

cipher = get_cipher_key()

def load_data():
    if os.path.exists("user_data.json"):
        with open("user_data.json", "r") as f:
            return json.load(f)
    return {}

def save_data(data):
    with open("user_data.json", "w") as f:
        json.dump(data, f, indent=4)

def hash_password(password):
    salt = b"static_salt_value"
    return hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000).hex()

def encrypt_text(text):
    return cipher.encrypt(text.encode()).decode()

def decrypt_text(encrypted):
    return cipher.decrypt(encrypted.encode()).decode()

def is_locked(user_data):
    if "lockout_time" in user_data:
        lock_time = datetime.fromtimestamp(user_data["lockout_time"])
        if datetime.now() < lock_time:
            return True, (lock_time - datetime.now()).seconds
    return False, 0

users = load_data()

st.set_page_config(page_title="🔐 Secure Encryption App", page_icon="🔒")
st.title("🔐 Secure Data Encryption System")

menu = ["Login", "Register", "Forgot Password"]
choice = st.sidebar.selectbox("Choose Action", menu)

if choice == "Register":
    st.subheader("📝 Create Account")
    username = st.text_input("Choose username")
    password = st.text_input("Choose password", type="password")
    security_answer = st.text_input(" Enter your security phrase?")

    if st.button("Register"):
        if username in users:
            st.error("Username already exists.")
        elif not username or not password or not security_answer:
            st.warning("Please fill all fields.")
        else:
            users[username] = {
                "password": hash_password(password),
                "security_answer": security_answer.lower(),
                "encrypted_data": "",
                "failed_attempts": 0,
                "lockout_time": 0
            }
            save_data(users)
            st.success("Account created successfully!")

elif choice == "Login":
    st.subheader("🔑 Login")
    username = st.text_input("Username")
    password = st.text_input("Password", type="password")

    if st.button("Login"):
        if username not in users:
            st.error("User not found.")
        else:
            user = users[username]
            locked, seconds_left = is_locked(user)
            if locked:
                st.warning(f"Account locked. Try again in {seconds_left} seconds.")
            elif hash_password(password) == user["password"]:
                user["failed_attempts"] = 0
                user["lockout_time"] = 0
                save_data(users)
                st.success(f"Welcome {username}!")

                st.subheader("🔒 Secure Data Section")
                action = st.radio("Action", ["Encrypt Data", "Decrypt Data"])

                if action == "Encrypt Data":
                    input_text = st.text_area("Enter text to encrypt")
                    if st.button("Encrypt & Save"):
                        users[username]["encrypted_data"] = encrypt_text(input_text)
                        save_data(users)
                        st.success("Data encrypted and saved.")
                else:
                    if user["encrypted_data"]:
                        if st.button("Decrypt"):
                            try:
                                decrypted = decrypt_text(user["encrypted_data"])
                                st.success(f"Decrypted: {decrypted}")
                            except:
                                st.error("Error decrypting.")
                    else:
                        st.warning("No data to decrypt.")
            else:
                user["failed_attempts"] += 1
                if user["failed_attempts"] >= 3:
                    lockout_duration = timedelta(seconds=30)
                    user["lockout_time"] = (datetime.now() + lockout_duration).timestamp()
                    st.error("Too many attempts. Account locked for 30 seconds.")
                else:
                    st.error("Incorrect password.")
                save_data(users)

elif choice == "Forgot Password":
    st.subheader("🔁 Reset Password")
    username = st.text_input("Enter your username")

    if username not in users:
        st.error("Username not found.")
    else:
        answer = st.text_input("Enter your security phrase?")
        new_pass = st.text_input("New password", type="password")

        if st.button("Reset"):
            if answer.lower() == users[username]["security_answer"]:
                users[username]["password"] = hash_password(new_pass)
                users[username]["failed_attempts"] = 0
                users[username]["lockout_time"] = 0
                save_data(users)
                st.success("Password reset successful.")
            else:
                st.error("Incorrect security answer.")
