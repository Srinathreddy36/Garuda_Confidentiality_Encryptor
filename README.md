🔐 Garuda Confidential Encryptor
Project 11 of the Garuda Sentinel Mission
Secure File Encryption with Built-in Integrity using AES-GCM and Password-Based Key Derivation.

📘 Overview
Garuda Confidential Encryptor provides robust protection for sensitive files by combining:

Confidentiality: Encrypts file contents using AES in Galois/Counter Mode (GCM).

Integrity: Automatically generates and verifies authentication tags.

Password-Based Key Derivation: Uses PBKDF2 with SHA-256 and a random salt to generate strong encryption keys from user-defined passwords.

Compromise Detection: Flags potential confidentiality breaches if wrong passwords are entered during decryption.

🚀 Features
🔑 Password-protected encryption

🔐 Authenticated encryption using AES-GCM (confidentiality + integrity)

🧪 Integrity verification using GCM tag during decryption

🚨 Confidentiality compromise warning on failed attempts

🛠️ Easy to use CLI for both encryption and decryption

🔁 Repeatable, secure, and portable process

🛠️ How It Works
🔒 Encryption Flow
User selects a file and provides a master password.

A random 16-byte salt is generated.

A key is derived from the password using PBKDF2 + SHA256.

AES-GCM is used to encrypt the file, producing:

nonce (12 bytes)

tag (16 bytes)

ciphertext

The resulting encrypted file includes:
salt || nonce || tag || ciphertext

🔓 Decryption Flow
User provides the .encrypted file and the master password.

The system extracts the salt, nonce, tag, and ciphertext.

The same key is derived from the password.

If decryption succeeds and tag verifies: ✅ File is authentic.

If password fails once and succeeds later: ⚠️ Shows compromise warning.

🔧 Requirements
Python 3.x

pycryptodome

bash
Copy
Edit
pip install pycryptodome💻 Usage
🔐 Encrypt a file
bash
Copy
Edit
python confidential_encryptor.py
Choose option 1 and follow the prompts to select a file and enter a password.

🔓 Decrypt a file
bash
Copy
Edit
python confidential_encryptor.py
Choose option 2, provide the .encrypted file, and enter the correct password.
🚧 Future Goals
Extend encryption to work over cloud storage (e.g., upload/download securely).

Add file expiration or automatic wipe support.

Integrate digital signatures (public key) for source authentication.

GUI-based version for broader adoption.

🛡️ Garuda Sentinel Mission
This project is part of the Garuda Sentinel initiative — a personal mission to build cybersecurity tools with real-world relevance based on deep cryptographic principles, inspired by the book Serious Cryptography.

📜 License
This project is open-source and free to use for educational and personal cybersecurity projects.
