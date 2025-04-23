# secure_data_encryption

## Secure Encryption & Decryption
Encrypt data using Caesar cipher or Fernet (from cryptography library).
Decrypt only when the correct passkey is provided.

## Authentication & Security
Allow three attempts before forcing a reauthorization/login page.
Display failed attempts count.

# Streamlit UI (User-Friendly Interface)
-- Home Page

-- Insert Data Page

-- Retrieve Data Page

-- Login Page:

## 🔹 Additional Challenges
Data Persistence

Store encrypted data in a JSON file instead of memory.
Load data on app startup.
Advanced Security Features

Time-based lockout for failed attempts.
Use PBKDF2 hashing instead of SHA-256 for extra security.
Multi-User System

Allow multiple users to store and retrieve their own data.
Use a user authentication system with Streamlit.
