import os
import base64
import hashlib
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

import json

BLOCK_SIZE = 128  # AES block size in bits

class PasswordManager:

    def __init__(self, storage_file="passwords.json"):
            self.aes_key = None
            self.master_password = None
            self.master_hash = None
            self.password_store = {}
            self.storage_file = storage_file

    def first_time_setup(self, password):
        self.master_password = password
        self.master_hash = self.hash_password(password)
        self.aes_key = self.derive_key(password)
        self.password_store = {}
        self.save_passwords()
        print("🔐 Master password set.\n")

# --- Master password setup and verification ---

    def login_with_password(self, password):
        self.master_password = password
        self.master_hash = self.hash_password(password)
        self.aes_key = self.derive_key(password)
        self.load_passwords()

    """def set_master_password(self):
        password = input("Set your master password: ")
        self.master_hash = self.hash_password(password)
        self.aes_key = self.derive_key(password)
        print("🔐 Master password set.\n")"""

    def verify_master_password(self):
        #attempt = input("Enter master password to access the system: ")
        if self.hash_password(self.master_password) == self.master_hash:
            self.aes_key = self.derive_key(self.master_password)
            print(" Access granted.\n")
            return True
        else:
            print("X Incorrect master password. Access denied.")
            return False


    def hash_password(self, password: str) -> str:
        return hashlib.sha256(password.encode()).hexdigest()

    def derive_key(self, password: str) -> bytes:
        return hashlib.sha256(password.encode()).digest()

    # --- AES Encryption / Decryption ---
    def encrypt(self, plaintext: str) -> str:
        iv = os.urandom(16)
        padder = padding.PKCS7(BLOCK_SIZE).padder()
        padded_data = padder.update(plaintext.encode()) + padder.finalize()

        cipher = Cipher(algorithms.AES(self.aes_key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

        return base64.b64encode(iv + encrypted_data).decode()

    def decrypt(self, encoded_data: str) -> str:
        raw_data = base64.b64decode(encoded_data.encode())
        iv = raw_data[:16]
        encrypted_data = raw_data[16:]

        cipher = Cipher(algorithms.AES(self.aes_key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted_padded = decryptor.update(encrypted_data) + decryptor.finalize()

        unpadder = padding.PKCS7(BLOCK_SIZE).unpadder()
        decrypted_data = unpadder.update(decrypted_padded) + unpadder.finalize()

        return decrypted_data.decode()

    # --- Password store/retrieve ---
    def store_password(self):
        site = input("Enter site name: ")
        site_password = input(f"Enter password for {site}: ")
        encrypted = self.encrypt(site_password)
        self.password_store[site] = encrypted
        self.save_passwords() # stores in the json file

        print(f" Password for '{site}' stored securely.")



    def retrieve_password(self):
        site = input("Enter site name to retrieve password: ")
        if site in self.password_store:
            try:
                decrypted = self.decrypt(self.password_store[site])
                print(f"🔓 Password for '{site}': {decrypted}")
            except Exception:
                print(" X Failed to decrypt. Wrong key?")
        else:
            print("!!! No password stored for that site.")

    # --- Menu ---
    def show_menu(self):
        while True:
            print("\n--- Password Manager Menu ---")
            print("1. Store new password")
            print("2. Retrieve password")
            print("3. Exit")

            choice = input("Choose an option (1/2/3): ")

            if choice == "1":
                self.store_password()
            elif choice == "2":
                self.retrieve_password()
            elif choice == "3":
                print(" Exiting password manager. Goodbye!")
                break
            else:
                print("X Invalid option. Please choose 1, 2, or 3.")

    def save_passwords(self):
        try:
            with open(self.storage_file, "w") as f:
                json.dump(self.password_store, f)
            print("Passwords saved to file.")
        except Exception as e:
            print("X Error saving passwords:", e)

    def load_passwords(self):
        if os.path.exists(self.storage_file):
            try:
                with open(self.storage_file, "r") as f:
                    self.password_store = json.load(f)
                print("#### Loaded existing passwords from file.")
            except Exception as e:
                print("!! Failed to load saved passwords:", e)
        else:
            print("# No saved password file found")





# def main():
#     manager = PasswordManager()
#     manager.set_master_password()

#     if manager.verify_master_password():
#         manager.show_menu()



def main():
    manager = PasswordManager()

    if not os.path.exists(manager.storage_file):
        print("# No saved password file found \n")
        print("""Welcome!
This is your personal, secure password manager.

🔑 The first time you use the vault, you’ll be asked to create a master password.
This password will be used to encrypt and unlock all your saved credentials.

🔐 You can:
 - Save passwords for different websites or services
 - View previously saved passwords (only if you enter the correct master password)
 - Keep all your data encrypted and secure

🧠 Remember: If you forget your master password, your stored passwords can't be recovered!

Let's get started!
""")
        pw = input("Set your master password: ")
        manager.first_time_setup(pw)
        manager.show_menu()
    else:
        pw = input("Enter master password to access the system: ")
        manager.login_with_password(pw)
        if manager.verify_master_password():
            manager.show_menu()

if __name__ == "__main__":
    main()
