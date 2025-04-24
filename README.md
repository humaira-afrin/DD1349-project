# DD1349-project


# 🔐 PasswordVault – A Simple Password Manager

## Project Description
**PasswordVault** is a lightweight password manager with a graphical user interface (GUI) built in **...**  
It allows users to:
- Add and store login credentials (e.g. website, username, password)
- View saved credentials in a list
- Securely encrypt and decrypt all data using symmetric encryption (AES)  
With AES encryption:  
	  -	You encrypt all data before saving it to a file  
	  -	Only someone who knows the master password (i.e., the key) can decrypt and read the contents  
	  -	If someone opens the file directly, they will only see unreadable “garbage” data  
- Lock access behind a master password

This project is developed as part of the **DD1349 - Software Development with Java (Projinda)** course at KTH.

The goal is to deliver a **Minimum Viable Product (MVP)** with essential functionality while keeping the technical complexity manageable.

---

## 🛠 Installation & Usage

### ✅ Requirements

- Python 3.8 or higher
- `pip` (Python package installer)

### 📦 Dependencies
```bash
pip install cryptography tk
```
### ▶️ Run the application
python xxx.py

**Att komplettera**

### 💻 Tech Stack: 
- Python – main programming language
- Tkinter – GUI framework
- cryptography – Used for AES encryption and secure key derivation (version 44.0.2) https://pypi.org/project/cryptography/

### Sources
- Understanting AES : https://www.youtube.com/watch?v=O4xNJsjtN6E
