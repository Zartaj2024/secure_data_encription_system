import streamlit as st
import hashlib
from cryptography.fernet import Fernet, InvalidToken
import json
from datetime import datetime, timedelta
from pathlib import Path
import base64
import os

# =============================================
# Configuration Constants
# =============================================
DATA_FILE = "secure_data.json"  # File to store encrypted data
MAX_ATTEMPTS = 3               # Maximum allowed failed attempts
LOCKOUT_TIME = 300             # 5 minutes lockout (in seconds)
MIN_PASSKEY_LENGTH = 8         # Minimum passkey length requirement
DEFAULT_SALT = b'secure_salt_' # Default salt for key derivation

# =============================================
# Session State Initialization
# =============================================
def init_session_state():
    """Initialize all required session state variables with proper defaults"""
    defaults = {
        'stored_data': {},
        'failed_attempts': 0,
        'locked_until': None,
        'authenticated': False,
        'current_user': None,
        'current_page': "home",
        'last_action': None
    }
    
    for key, value in defaults.items():
        if key not in st.session_state:
            st.session_state[key] = value
    
    # Load data only once when initializing
    if not st.session_state.stored_data:
        st.session_state.stored_data = load_data()

# =============================================
# Data Persistence Functions
# =============================================
def load_data():
    """Safely load encrypted data from JSON file"""
    try:
        if not Path(DATA_FILE).exists():
            return {}
            
        with open(DATA_FILE, 'r') as f:
            data = json.load(f)
            # Validate loaded data structure
            if not isinstance(data, dict):
                st.error("Invalid data format in storage file")
                return {}
            return data
    except json.JSONDecodeError:
        st.error("Corrupted data file - starting with empty storage")
        return {}
    except Exception as e:
        st.error(f"Error loading data: {str(e)}")
        return {}

def save_data():
    """Safely save encrypted data to JSON file"""
    try:
        if not isinstance(st.session_state.stored_data, dict):
            st.error("Invalid data format - cannot save")
            return
            
        with open(DATA_FILE, 'w') as f:
            json.dump(st.session_state.stored_data, f, indent=2)
    except PermissionError:
        st.error("Permission denied - cannot save data")
    except Exception as e:
        st.error(f"Error saving data: {str(e)}")

# =============================================
# Cryptographic Functions
# =============================================
def generate_key(passkey):
    """
    Securely derive encryption key from passkey using PBKDF2-HMAC-SHA256
    Args:
        passkey (str): User-provided passkey
    Returns:
        bytes: Fernet-compatible encryption key
    Raises:
        ValueError: If passkey is empty or invalid
    """
    if not passkey or not isinstance(passkey, str):
        raise ValueError("Invalid passkey")
    
    try:
        kdf = hashlib.pbkdf2_hmac(
            'sha256',
            passkey.encode('utf-8'),
            DEFAULT_SALT,
            100000  # Number of iterations
        )
        return base64.urlsafe_b64encode(kdf[:32])  # Fernet needs exactly 32 bytes
    except Exception as e:
        st.error(f"Key generation failed: {str(e)}")
        raise

def encrypt_text(text, passkey):
    """
    Encrypt text using Fernet symmetric encryption with proper error handling
    Args:
        text (str): Plaintext to encrypt
        passkey (str): User's passkey
    Returns:
        str: Encrypted ciphertext or None on failure
    """
    if not text or not passkey:
        st.error("Text and passkey cannot be empty")
        return None
    
    try:
        key = generate_key(passkey)
        fernet = Fernet(key)
        encrypted = fernet.encrypt(text.encode('utf-8'))
        return encrypted.decode('utf-8')
    except ValueError as e:
        st.error(f"Encryption failed: {str(e)}")
    except Exception as e:
        st.error(f"Unexpected encryption error: {str(e)}")
    return None

def decrypt_text(encrypted_text, passkey):
    """
    Decrypt text using Fernet symmetric encryption with proper error handling
    Args:
        encrypted_text (str): Ciphertext to decrypt
        passkey (str): User's passkey
    Returns:
        str: Decrypted plaintext or None on failure
    """
    if not encrypted_text or not passkey:
        return None
    
    try:
        key = generate_key(passkey)
        fernet = Fernet(key)
        decrypted = fernet.decrypt(encrypted_text.encode('utf-8'))
        return decrypted.decode('utf-8')
    except InvalidToken:
        return None  # Expected for wrong passkey
    except ValueError as e:
        st.error(f"Decryption failed: {str(e)}")
    except Exception as e:
        st.error(f"Unexpected decryption error: {str(e)}")
    return None

def hash_passkey(passkey):
    """
    Securely hash passkey with SHA-256 and salt
    Args:
        passkey (str): User's plaintext passkey
    Returns:
        str: Hashed passkey or None on failure
    """
    if not passkey:
        return None
        
    try:
        salt = "secure_system_salt" + str(DEFAULT_SALT)
        return hashlib.sha256((passkey + salt).encode('utf-8')).hexdigest()
    except Exception as e:
        st.error(f"Hashing failed: {str(e)}")
        return None

# =============================================
# UI Page Functions
# =============================================
def home_page():
    """Main landing page with navigation options"""
    st.title("🔒 Secure Data Storage System")
    
    # Check account lock status
    if st.session_state.locked_until:
        if datetime.now() < st.session_state.locked_until:
            remaining = (st.session_state.locked_until - datetime.now()).seconds // 60 + 1
            st.error(f"Account locked. Please try again in {remaining} minutes.")
            return
        else:
            # Lock expired, reset the state
            st.session_state.locked_until = None
            st.session_state.failed_attempts = 0
    
    # Authentication check
    if not st.session_state.authenticated:
        login_page()
        return
    
    # Main interface
    st.success(f"Welcome back, {st.session_state.current_user}!")
    st.write(f"Total stored items: {len(st.session_state.stored_data)}")
    
    # Navigation buttons
    cols = st.columns(2)
    with cols[0]:
        if st.button("💾 Store New Data"):
            st.session_state.current_page = "store"
            st.rerun()
    with cols[1]:
        if st.button("🔍 Retrieve Data"):
            st.session_state.current_page = "retrieve"
            st.rerun()

def login_page():
    """User authentication page with validation"""
    st.title("🔑 Login")
    
    with st.form("login_form"):
        username = st.text_input("Username", key="login_username")
        password = st.text_input("Password", type="password", key="login_password")
        
        if st.form_submit_button("Login"):
            if not username or not password:
                st.error("Please enter both username and password")
            else:
                # Simple authentication (replace with proper auth in production)
                st.session_state.authenticated = True
                st.session_state.current_user = username.strip()
                st.session_state.failed_attempts = 0
                st.session_state.locked_until = None
                st.rerun()

def store_data_page():
    """Page for storing new encrypted data with validation"""
    st.title("💾 Store Data Securely")
    
    with st.form("store_form"):
        data_id = st.text_input("Unique Data Identifier", 
                              help="A unique name to identify your data")
        secret_text = st.text_area("Text to Store Securely", height=150)
        passkey = st.text_input("Encryption Passkey", type="password",
                              help=f"Must be at least {MIN_PASSKEY_LENGTH} characters")
        confirm_passkey = st.text_input("Confirm Passkey", type="password")
        
        if st.form_submit_button("Encrypt and Store"):
            # Validate all fields
            if not all([data_id.strip(), secret_text.strip(), passkey, confirm_passkey]):
                st.error("All fields are required!")
            elif passkey != confirm_passkey:
                st.error("Passkeys don't match!")
            elif len(passkey) < MIN_PASSKEY_LENGTH:
                st.error(f"Passkey must be at least {MIN_PASSKEY_LENGTH} characters")
            elif data_id in st.session_state.stored_data:
                st.error("This identifier already exists. Please choose a different one.")
            else:
                # Encrypt and store the data
                encrypted_text = encrypt_text(secret_text, passkey)
                if encrypted_text:
                    hashed_pw = hash_passkey(passkey)
                    if not hashed_pw:
                        st.error("Failed to secure passkey")
                        return
                    
                    st.session_state.stored_data[data_id] = {
                        "encrypted_text": encrypted_text,
                        "passkey_hash": hashed_pw,
                        "owner": st.session_state.current_user,
                        "created_at": datetime.now().isoformat()
                    }
                    save_data()
                    st.success("Data encrypted and stored securely!")
                    st.session_state.current_page = "home"
                    st.rerun()

    if st.button("← Back to Home"):
        st.session_state.current_page = "home"
        st.rerun()

def retrieve_data_page():
    """Page for retrieving and decrypting stored data with attempt tracking"""
    st.title("🔍 Retrieve Encrypted Data")
    
    # Check attempt limit
    if st.session_state.failed_attempts >= MAX_ATTEMPTS:
        if not st.session_state.locked_until:
            st.session_state.locked_until = datetime.now() + timedelta(seconds=LOCKOUT_TIME)
            save_data()
        
        remaining = (st.session_state.locked_until - datetime.now()).seconds // 60 + 1
        st.error(f"Too many failed attempts. System locked for {remaining} minutes.")
        st.session_state.current_page = "home"
        st.rerun()
        return
    
    with st.form("retrieve_form"):
        data_id = st.text_input("Enter Data Identifier")
        passkey = st.text_input("Enter Passkey", type="password")
        
        if st.form_submit_button("Decrypt Data"):
            if not data_id or not passkey:
                st.error("Both fields are required!")
            elif data_id not in st.session_state.stored_data:
                st.error("Data not found!")
            else:
                data = st.session_state.stored_data[data_id]
                
                # Verify ownership
                if data.get("owner") != st.session_state.current_user:
                    st.error("Access denied. You don't own this data.")
                else:
                    # Verify passkey
                    hashed_input = hash_passkey(passkey)
                    if not hashed_input or hashed_input != data["passkey_hash"]:
                        st.session_state.failed_attempts += 1
                        remaining = MAX_ATTEMPTS - st.session_state.failed_attempts
                        st.error(f"Incorrect passkey! {remaining} attempts remaining.")
                        save_data()
                    else:
                        # Decrypt data
                        decrypted_text = decrypt_text(data["encrypted_text"], passkey)
                        if decrypted_text:
                            st.session_state.failed_attempts = 0
                            st.success("✅ Data decrypted successfully!")
                            st.text_area("Decrypted Content", decrypted_text, height=200)
                        else:
                            st.error("Decryption failed. Incorrect passkey?")

    if st.button("← Back to Home"):
        st.session_state.current_page = "home"
        st.rerun()

# =============================================
# Main Application
# =============================================
def main():
    """Main application entry point with error boundary"""
    try:
        # Configure Streamlit page settings
        st.set_page_config(
            page_title="Secure Data Storage",
            page_icon="🔒",
            layout="centered",
            initial_sidebar_state="collapsed"
        )
        
        # Initialize session state
        init_session_state()
        
        # Page routing
        page_functions = {
            "home": home_page,
            "store": store_data_page,
            "retrieve": retrieve_data_page
        }
        
        current_page = st.session_state.get("current_page", "home")
        if current_page in page_functions:
            page_functions[current_page]()
        else:
            st.error("Invalid page requested")
            st.session_state.current_page = "home"
            st.rerun()
            
    except Exception as e:
        st.error(f"Critical application error: {str(e)}")
        st.write("Please refresh the page and try again")

if __name__ == "__main__":
    main()