import os
import getpass
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes

def read_file_content(path):
    try:
        with open(path, 'rb') as f:
            return f.read()
    except FileNotFoundError:
        print("❌ File not found. Please check the path.")
        return None

def encrypt_file():
    file_path = input("Enter the path to the local file to encrypt: ").strip()
    file_data = read_file_content(file_path)
    if file_data is None:
        return

    master_password = getpass.getpass("Set a master password: ")

    # Derive key
    salt = get_random_bytes(16)
    key = PBKDF2(master_password, salt, dkLen=32, count=100000, hmac_hash_module=SHA256)

    # Encrypt using AES-GCM
    nonce = get_random_bytes(12)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(file_data)

    # Save encrypted file (salt + nonce + tag + ciphertext)
    encrypted_data = salt + nonce + tag + ciphertext
    output_path = file_path + ".encrypted"

    with open(output_path, "wb") as f:
        f.write(encrypted_data)

    print(f"✅ File encrypted and saved as: {output_path}")

def decrypt_file():
    encrypted_path = input("Enter the path to the encrypted file: ").strip()
    encrypted_data = read_file_content(encrypted_path)
    if encrypted_data is None:
        return

    failed_attempt = False  # Track if any previous attempt failed

    while True:
        master_password = getpass.getpass("Enter the master password: ")

        try:
            # Extract salt, nonce, tag, and ciphertext
            salt = encrypted_data[:16]
            nonce = encrypted_data[16:28]
            tag = encrypted_data[28:44]
            ciphertext = encrypted_data[44:]

            # Derive key
            key = PBKDF2(master_password, salt, dkLen=32, count=100000, hmac_hash_module=SHA256)

            # Decrypt
            cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
            decrypted_data = cipher.decrypt_and_verify(ciphertext, tag)

            output_path = encrypted_path.replace(".encrypted", ".decrypted")
            with open(output_path, "wb") as f:
                f.write(decrypted_data)

            print(f"\n✅ File decrypted and saved as: {output_path}")
            if failed_attempt:
                print("⚠️ WARNING: A previous failed attempt was detected.")
                print("🔐 Confidentiality may be compromised.")
            break

        except Exception:
            print("❌ Decryption failed. Possible wrong password or file tampering.")
            failed_attempt = True
            try_again = input("Do you want to try again? (y/n): ").lower()
            if try_again != 'y':
                break

def main():
    print("\n🛡️ Confidential File Encryption with Integrity (AES-GCM)")
    print("1. Encrypt a file")
    print("2. Decrypt a file")
    
    choice = input("Enter your choice (1 or 2): ").strip()

    if choice == '1':
        encrypt_file()
    elif choice == '2':
        decrypt_file()
    else:
        print("Invalid choice. Please enter 1 or 2.")

if __name__ == "__main__":
    main()
