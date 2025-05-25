import streamlit as st
import hashlib
import json
import time
from cryptography.fernet import Fernet
import base64
import uuid

# Initialize session state
if 'failed_attempts' not in st.session_state:
    st.session_state.failed_attempts = 0
if 'stored_data' not in st.session_state:
    st.session_state.stored_data = {}
if 'current_page' not in st.session_state:
    st.session_state.current_page = "Home"
if 'last_attempt_time' not in st.session_state:
    st.session_state.last_attempt_time = 0

# Functions
def hash_passkey(passKey):
    return hashlib.sha256(passKey.encode()).hexdigest()

def generate_key_from_passkey(passKey):
    hashed = hashlib.sha256(passKey.encode()).digest()
    return base64.urlsafe_b64encode(hashed[:32])

def encrypt_data(text, passkey):
    key = generate_key_from_passkey(passkey)
    cipher = Fernet(key)
    return cipher.encrypt(text.encode()).decode()

def decrypt_data(encrypted_text, passkey, data_id):
    try:
        hashed_passkey = hash_passkey(passkey)
        if data_id in st.session_state.stored_data and st.session_state.stored_data[data_id]["passKey"] == hashed_passkey:
            key = generate_key_from_passkey(passkey)
            cipher = Fernet(key)
            decrypted = cipher.decrypt(encrypted_text.encode()).decode()
            st.session_state.failed_attempts = 0
            return decrypted
        else:
            st.session_state.failed_attempts += 1
            st.session_state.last_attempt_time = time.time()
            return None
    except Exception:
        st.session_state.failed_attempts += 1
        st.session_state.last_attempt_time = time.time()

def generate_data_id():
    return str(uuid.uuid4())

def reset_failed_attempts():
    st.session_state.failed_attempts = 0

def change_page(page):
    st.session_state.current_page = page

# Page Title
st.markdown("<h1 style='text-align: center; color: #4B8BBE;'>🔐 Secure Data Encryption App</h1>", unsafe_allow_html=True)
st.markdown("<hr>", unsafe_allow_html=True)

# Sidebar Navigation
menu = ["Home", "Store Data", "Retrieve Data", "Login"]
choice = st.sidebar.radio("📁 Menu", menu, index=menu.index(st.session_state.current_page))
st.session_state.current_page = choice

# Too many failed attempts
if st.session_state.failed_attempts >= 3:
    st.session_state.current_page = "Login"
    st.warning("🚨 Too many failed attempts! Reauthorization required.")

# Home
if st.session_state.current_page == "Home":
    st.markdown("### 👋 Welcome!")
    st.write("This app helps you securely **store and retrieve data** using encryption and passkeys.")

    col1, col2 = st.columns(2)
    with col1:
        if st.button("📝 Store New Data", use_container_width=True):
            change_page("Store Data")
    with col2:
        if st.button("🔍 Retrieve Data", use_container_width=True):
            change_page("Retrieve Data")

    st.info(f"📦 Total Stored Entries: `{len(st.session_state.stored_data)}`")

# Store Data
elif st.session_state.current_page == "Store Data":
    st.markdown("### 📝 Store Data Securely")

    with st.form(key="store_form"):
        user_data = st.text_area("Enter the data you want to encrypt")
        passKey = st.text_input("Create a Passkey", type="password")
        confirm_passkey = st.text_input("Confirm Passkey", type="password")
        submit = st.form_submit_button("Encrypt & Store")

        if submit:
            if not user_data or not passKey or not confirm_passkey:
                st.error("❌ All fields are required.")
            elif passKey != confirm_passkey:
                st.error("❌ Passkeys do not match.")
            else:
                data_id = generate_data_id()
                encrypted_text = encrypt_data(user_data, passKey)
                hashed_passkey = hash_passkey(passKey)

                st.session_state.stored_data[data_id] = {
                    "encrypted_text": encrypted_text,
                    "passKey": hashed_passkey
                }

                st.success("✅ Data encrypted and stored successfully!")
                st.code(data_id, language="text")
                st.info("🔑 Save this Data ID — you'll need it to retrieve your data.")

# Retrieve Data
elif st.session_state.current_page == "Retrieve Data":
    st.markdown("### 🔍 Retrieve Encrypted Data")

    attempts_remaining = 3 - st.session_state.failed_attempts
    st.info(f"🔒 Attempts Remaining: `{attempts_remaining}`")

    with st.form(key="retrieve_form"):
        data_id = st.text_input("Enter your Data ID")
        passKey = st.text_input("Enter your Passkey", type="password")
        submit = st.form_submit_button("Decrypt")

        if submit:
            if not data_id or not passKey:
                st.error("❌ Both fields are required.")
            elif data_id not in st.session_state.stored_data:
                st.error("❌ Data ID not found.")
            else:
                encrypted_text = st.session_state.stored_data[data_id]["encrypted_text"]
                decrypted = decrypt_data(encrypted_text, passKey, data_id)
                if decrypted:
                    st.success("✅ Decryption Successful!")
                    st.text_area("🔓 Your Decrypted Data:", value=decrypted, height=150)
                else:
                    st.error(f"❌ Incorrect passkey. Attempts left: `{3 - st.session_state.failed_attempts}`")
                    if st.session_state.failed_attempts >= 3:
                        st.warning("🚨 Too many failed attempts! Redirecting to login page.")
                        st.rerun()

# Login
elif st.session_state.current_page == "Login":
    st.markdown("### 🔐 Reauthorization Required")

    wait_time = 10
    if time.time() - st.session_state.last_attempt_time < wait_time:
        remaining = int(wait_time - (time.time() - st.session_state.last_attempt_time))
        st.warning(f"⏳ Please wait {remaining} seconds before trying again.")
    else:
        login_pass = st.text_input("Enter Master Password", type="password")
        if st.button("Login"):
            if login_pass == "admin123":
                reset_failed_attempts()
                st.success("✅ Reauthorized successfully.")
                change_page("Home")
                st.rerun()
            else:
                st.error("❌ Incorrect master password.")

# Footer
st.markdown("<hr>", unsafe_allow_html=True)
st.markdown("<center>🔐 Secure Data Encryption System | Educational Use Only</center>", unsafe_allow_html=True)
