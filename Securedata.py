import streamlit as st
import hashlib
from cryptography.fernet import Fernet

# Generate or load Fernet key
if "fernet_key" not in st.session_state:
    st.session_state.fernet_key = Fernet.generate_key()

cipher = Fernet(st.session_state.fernet_key)


# Initialize session state variables
if "failed_attempts" not in st.session_state:
    st.session_state.failed_attempts = 0
if "is_authenticated" not in st.session_state:
    st.session_state.is_authenticated = False
if "users" not in st.session_state:
    st.session_state.users = {}  # {"username": "hashed_password"}
if "stored_data" not in st.session_state:
    st.session_state.stored_data = {}  # {encrypted_text: {"encrypted_text": ..., "passkey": ...}}

# Utility: Hashing function
def hash_passkey(passkey):
    return hashlib.sha256(passkey.encode()).hexdigest()

# Encrypt
def encrypt_data(text):
    return cipher.encrypt(text.encode()).decode()

# Decrypt
def decrypt_data(encrypted_text, passkey):
    hashed = hash_passkey(passkey)
    data = st.session_state.stored_data.get(encrypted_text)
    if data and data["passkey"] == hashed:
        st.session_state.failed_attempts = 0
        return cipher.decrypt(encrypted_text.encode()).decode()
    else:
        st.session_state.failed_attempts += 1
        return None

# App Layout
st.set_page_config(page_title="🔐 Secure Data Encryption System")
st.title("🔐 Secure Data Encryption System")

menu = ["Home", "Register", "Login", "Store Data", "Retrieve Data"]
choice = st.sidebar.selectbox("Navigation", menu)

# Home Page
if choice == "Home":
    st.subheader("🏠 Welcome")
    st.write("Securely **store** and **retrieve** encrypted data with a unique passkey.")

# Register Page
elif choice == "Register":
    st.subheader("📝 Register New Account")
    username = st.text_input("Username")
    password = st.text_input("Password", type="password")

    if st.button("Register"):
        if username and password:
            hashed_password = hash_passkey(password)
            if username in st.session_state.users:
                st.warning("⚠️ Username already exists.")
            else:
                st.session_state.users[username] = hashed_password
                st.success("✅ Registered successfully!")
        else:
            st.error("⚠️ Both fields required.")

# Login Page
elif choice == "Login":
    st.subheader("🔑 Reauthentication Required")
    username = st.text_input("Username")
    password = st.text_input("Password", type="password")

    if st.button("Login"):
        hashed_password = hash_passkey(password)
        if username in st.session_state.users and st.session_state.users[username] == hashed_password:
            st.session_state.failed_attempts = 0
            st.session_state.is_authenticated = True
            st.success("✅ Login successful!")
        else:
            st.error("❌ Invalid username or password.")

# Store Data
elif choice == "Store Data":
    st.subheader("📂 Store Data Securely")
    user_data = st.text_area("Enter your data:")
    passkey = st.text_input("Enter a passkey:", type="password")

    if st.button("Encrypt & Save"):
        if user_data and passkey:
            hashed = hash_passkey(passkey)
            encrypted = encrypt_data(user_data)
            st.session_state.stored_data[encrypted] = {"encrypted_text": encrypted, "passkey": hashed}
            st.success("✅ Data encrypted and stored successfully.")
            st.code(encrypted, language="text")
        else:
            st.error("⚠️ Please fill in both fields.")

# Retrieve Data
elif choice == "Retrieve Data":
    if not st.session_state.is_authenticated:
        st.warning("🔒 You must login first!")
    else:
        st.subheader("🔍 Retrieve Encrypted Data")
        encrypted_input = st.text_area("Paste the encrypted data:")
        passkey = st.text_input("Enter your passkey ( while storing data ) :", type="password")

        if st.button("Decrypt"):
            if encrypted_input and passkey:
                decrypted = decrypt_data(encrypted_input, passkey)
                if decrypted:
                    st.success("✅ Decrypted Successfully:")
                    st.code(decrypted, language="text")
                else:
                    attempts_left = 3 - st.session_state.failed_attempts
                    st.error(f"❌ Incorrect passkey! Attempts left: {attempts_left}")
                    if st.session_state.failed_attempts >= 3:
                        st.warning("🔒 Too many failed attempts. Please login again.")
                        st.session_state.is_authenticated = False
            else:
                st.error("⚠️ Both fields are required.")
