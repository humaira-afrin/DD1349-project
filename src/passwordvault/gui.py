import tkinter as tk
from tkinter import messagebox
from aes_crypto import PasswordManager
import os  # För att kolla om filen finns

# Skapa GUI-klass
class PasswordVaultGUI:
    def __init__(self, root):
        self.manager = PasswordManager()
        self.root = root
        self.root.title("PasswordVault 🔐")
        self.root.geometry("600x500")
        self.root.configure(bg="#FFC0CB")

        if not os.path.exists(self.manager.storage_file):
            self.first_time_view()
        else:
            self.manager.load_passwords()
            self.login_view()

    def first_time_view(self):
        self.clear_window()

        frame = tk.Frame(self.root, bg="#FFC0CB")
        frame.pack(expand=True)

        welcome_msg = (
            "Welcome!\n\n"
            "This is your personal, secure password manager.\n\n"
            "🔑 First time here? Create a master password.\n"
            "This password is used to encrypt your saved passwords.\n\n"
            "🧠 Don't forget it, it can't be recovered!"
        )

        tk.Label(frame, text=welcome_msg, bg="#FFC0CB", font=("Arial", 12), justify="left", wraplength=400).pack(pady=10)

        tk.Label(frame, text="Set master password:", font=("Arial", 14), bg="#FFC0CB").pack(pady=10)
        self.new_pw_entry = tk.Entry(frame, font=("Arial", 12)) # , show="*"
        self.new_pw_entry.pack()

        tk.Button(frame, text="Create", font=("Arial", 12), command=self.set_first_master).pack(pady=10)

    def set_first_master(self):
        pw = self.new_pw_entry.get()
        if pw.strip() == "":
            messagebox.showwarning("Warning", "Password can't be empty!")
            return
        self.manager.first_time_setup(pw)
        messagebox.showinfo("Success", "Master password set! You can now log in.")
        self.login_view()

    def login_view(self):
        self.clear_window()

        frame = tk.Frame(self.root, bg="#FFC0CB")
        frame.pack(expand=True)

        tk.Label(frame, text="Enter master password:", font=("Arial", 18), bg="#FFC0CB").pack(pady=10)
        self.pw_entry = tk.Entry(frame, show="*", font=("Arial", 12))
        self.pw_entry.pack()

        tk.Button(frame, text="Login", command=self.verify_password, font=("Arial", 12)).pack(pady=10)

    def verify_password(self):
        entered = self.pw_entry.get()
        if self.manager.hash_password(entered) == self.manager.master_hash:
            self.manager.aes_key = self.manager.derive_key(entered)
            messagebox.showinfo("Access", "Access granted!")
            self.main_menu()
        else:
            messagebox.showerror("Error", "Wrong password!")

    def main_menu(self):
        self.clear_window()

        tk.Label(self.root, text="Welcome to PasswordVault", font=("Arial", 16), bg="#FFC0CB").pack(pady=20)

        tk.Button(self.root, text="Store new password", font=("Arial", 12), command=self.store_view).pack(pady=5)
        tk.Button(self.root, text="Retrieve password", font=("Arial", 12), command=self.retrieve_view).pack(pady=5)
        tk.Button(self.root, text="Exit", font=("Arial", 12), command=self.root.quit).pack(pady=20)

    def store_view(self):
        self.clear_window()

        tk.Label(self.root, text="Site name:", font=("Arial", 12), bg="#FFC0CB").pack()
        site_entry = tk.Entry(self.root)
        site_entry.pack()

        tk.Label(self.root, text="Password:", font=("Arial", 12), bg="#FFC0CB").pack()
        pw_entry = tk.Entry(self.root)
        pw_entry.pack()

        def store():
            site = site_entry.get()
            pw = pw_entry.get()
            self.manager.password_store[site] = self.manager.encrypt(pw)
            self.manager.save_passwords()
            messagebox.showinfo("Saved", f"Password for '{site}' saved.")
            self.main_menu()

        tk.Button(self.root, text="Save", font=("Arial", 12), command=store).pack(pady=10)

    def retrieve_view(self):
        self.clear_window()

        tk.Label(self.root, text="Enter site name:", font=("Arial", 12), bg="#FFC0CB").pack()
        site_entry = tk.Entry(self.root)
        site_entry.pack()

        def retrieve():
            site = site_entry.get()
            if site in self.manager.password_store:
                try:
                    decrypted = self.manager.decrypt(self.manager.password_store[site])
                    messagebox.showinfo("Password", f"Password for '{site}': {decrypted}")
                except Exception:
                    messagebox.showerror("Error", "Failed to decrypt.")
            else:
                messagebox.showwarning("Not found", "Site not found.")
            self.main_menu()

        tk.Button(self.root, text="Retrieve", font=("Arial", 12), command=retrieve).pack(pady=10)

    def clear_window(self):
        for widget in self.root.winfo_children():
            widget.destroy()

# Kör appen
if __name__ == "__main__":
    root = tk.Tk()
    app = PasswordVaultGUI(root)
    root.mainloop()