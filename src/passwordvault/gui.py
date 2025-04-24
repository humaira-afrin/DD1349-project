import tkinter as tk
from tkinter import messagebox
from aes_crypto import PasswordManager
import os

class PasswordVaultGUI:
    def __init__(self, root):
        self.manager = PasswordManager()
        self.root = root
        self.root.title("PasswordVault 🔐")
        self.root.geometry("600x500")
        self.root.configure(bg="#FFC0CB")  # Classic pink

        if not os.path.exists(self.manager.storage_file):
            self.first_time_view()
        else:
            self.manager.load_passwords()
            self.login_view()

    def style_button(self, button):
        button.configure(
            bg="white",
            fg="black",
            font=("Segoe UI", 12),
            relief="solid",
            bd=1,
            padx=10,
            pady=5
        )

    def first_time_view(self):
        self.clear_window()

        frame = tk.Frame(self.root, bg="#FFC0CB", padx=40, pady=40)
        frame.pack(expand=True)

        welcome_msg = (
            "👋 Welcome!\n\n"
            "This is your personal, secure password manager.\n\n"
            "🔑 First time here? Create a master password.\n"
            "This password is used to encrypt your saved passwords.\n\n"
            "🧠 Don't forget it, it can't be recovered!"
        )

        tk.Label(frame, text=welcome_msg, bg="#FFC0CB", font=("Segoe UI", 12), justify="left", wraplength=400).pack(pady=10)

        tk.Label(frame, text="Set master password:", font=("Segoe UI", 14), bg="#FFC0CB", fg="#333333").pack(pady=10)
        self.new_pw_entry = tk.Entry(frame, font=("Segoe UI", 12), show="*")
        self.new_pw_entry.pack(pady=5)

        create_btn = tk.Button(frame, text="Create", command=self.set_first_master)
        self.style_button(create_btn)
        create_btn.pack(pady=10)

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

        frame = tk.Frame(self.root, bg="#FFC0CB", padx=40, pady=40)
        frame.pack(expand=True)

        tk.Label(frame, text="Enter master password:", font=("Segoe UI", 16, "bold"), bg="#FFC0CB", fg="black").pack(pady=10)
        self.pw_entry = tk.Entry(frame, show="*", font=("Segoe UI", 12))
        self.pw_entry.pack(pady=5)

        login_btn = tk.Button(frame, text="Login", command=self.verify_password)
        self.style_button(login_btn)
        login_btn.pack(pady=10)

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
        frame = tk.Frame(self.root, bg="#FFC0CB", padx=40, pady=40)
        frame.pack(expand=True)

        tk.Label(frame, text="🔐 Welcome to PasswordVault", font=("Segoe UI", 18, "bold"), bg="#FFC0CB", fg="#333").pack(pady=20)
        self.root.update_idletasks()  # rendering happens directly

        btn_store = tk.Button(frame, text="Store new password", command=self.store_view)
        btn_retrieve = tk.Button(frame, text="Retrieve password", command=self.retrieve_view)
        btn_exit = tk.Button(frame, text="Exit", command=self.root.quit)

        for btn in [btn_store, btn_retrieve, btn_exit]:
            self.style_button(btn)
            btn.pack(pady=5)

    def store_view(self):
        self.clear_window()
        frame = tk.Frame(self.root, bg="#FFC0CB", padx=40, pady=40)
        frame.pack(expand=True)

        tk.Label(frame, text="Site name:", font=("Segoe UI", 12), bg="#FFC0CB").pack()
        site_entry = tk.Entry(frame)
        site_entry.pack(pady=5)

        tk.Label(frame, text="Password:", font=("Segoe UI", 12), bg="#FFC0CB").pack()
        pw_entry = tk.Entry(frame)
        pw_entry.pack(pady=5)

        def store():
            site = site_entry.get()
            pw = pw_entry.get()
            self.manager.password_store[site] = self.manager.encrypt(pw)
            self.manager.save_passwords()
            messagebox.showinfo("Saved", f"Password for '{site}' saved.")
            self.main_menu()

        save_btn = tk.Button(frame, text="Save", command=store)
        self.style_button(save_btn)
        save_btn.pack(pady=10)

        back_btn = tk.Button(frame, text="Back", command=self.main_menu)
        self.style_button(back_btn)
        back_btn.pack(pady=5)
        self.root.update_idletasks()


    def retrieve_view(self):
        self.clear_window()
        frame = tk.Frame(self.root, bg="#FFC0CB", padx=40, pady=40)
        frame.pack(expand=True)

        tk.Label(frame, text="Enter site name:", font=("Segoe UI", 12), bg="#FFC0CB").pack()
        site_entry = tk.Entry(frame)
        site_entry.pack(pady=5)

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

        retrieve_btn = tk.Button(frame, text="Retrieve", command=retrieve)
        self.style_button(retrieve_btn)
        retrieve_btn.pack(pady=10)

        back_btn = tk.Button(frame, text="Back", command=self.main_menu)
        self.style_button(back_btn)
        back_btn.pack(pady=5)
        self.root.update_idletasks()



    def clear_window(self):
        for widget in self.root.winfo_children():
            widget.destroy()

# Launch app
if __name__ == "__main__":
    root = tk.Tk()
    app = PasswordVaultGUI(root)
    root.mainloop()
