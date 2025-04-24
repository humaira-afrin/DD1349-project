# DD1349-project


# 🔐 PasswordVault – A Simple Password Manager

## 📝 Project Description

**PasswordVault** is a lightweight password manager with a graphical user interface (GUI) built in **Python**.  
It is designed to help users securely store and manage login credentials.

### ✨ Features:
- Add and store login credentials (e.g., website and password)
- View saved credentials through a simple GUI
- Securely encrypt and decrypt all data using symmetric encryption (AES)
- Lock access behind a master password

### 🔒 AES Encryption
PasswordVault uses AES encryption from the `cryptography` library:
- All data is encrypted before being saved to a file
- Only someone with the correct master password (used as key) can decrypt the data
- If someone tries to open the data file directly, they will only see unreadable “garbage” text

---

## 🚀 Installation & Usage

### ✅ Requirements
- Python 3.8 or higher
- `pip` (Python package installer)

### 📦 Install Dependencies
Install required libraries by running:
```bash
pip install cryptography tk
```

### ▶️ Run the Application

Make sure you are in the root directory of the project and run the GUI app with:
```
python src/passwordvault/gui.py
```
**Att komplettera**

### 💻 Tech Stack: 
- Python – main programming language
- Tkinter – GUI framework
- cryptography – Used for AES encryption and secure key derivation (version 44.0.2) https://pypi.org/project/cryptography/

### Sources
- Understanting AES : https://www.youtube.com/watch?v=O4xNJsjtN6E

## 📅 Weekly Milestones

We'll be using GitHub's **Issue Tracker** and **Milestones** to manage weekly development. 

## ✍️ Authors
Elsa Kieffer  
Humaira Afrin

## 🧪 MVP Goal

This application was developed as part of the DD1349 – Software Development with Java (Projinda) course at KTH Royal Institute of Technology.
The project aims to deliver a Minimum Viable Product (MVP) with essential functionality while keeping technical complexity manageable.


