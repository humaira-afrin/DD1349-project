import tkinter as tk
from tkinter import messagebox
from aes_crypto import PasswordManager

# Skapa GUI-klass
class PasswordVaultGUI:
    def __init__(self, root):
        self.manager = PasswordManager()
        self.manager.load_passwords()
        self.root = root
        self.root.title("PasswordVault 🔐")
        self.root.geometry("600x500")
        self.root.configure(bg="#FFC0CB")
        self.login_view()

    def login_view(self):
        self.clear_window()

        frame = tk.Frame(self.root, bg="#FFC0CB")
        frame.pack(expand=True)

        tk.Label(frame, text="Enter master password:", font=("Arial", 18)).pack(pady=10)
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

        tk.Label(self.root, text="Welcome to PasswordVault").pack(pady=10)

        tk.Button(self.root, text="Store new password", command=self.store_view).pack(pady=5)
        tk.Button(self.root, text="Retrieve password", command=self.retrieve_view).pack(pady=5)
        tk.Button(self.root, text="Exit", command=self.root.quit).pack(pady=20)

    def store_view(self):
        self.clear_window()

        tk.Label(self.root, text="Site name:").pack()
        site_entry = tk.Entry(self.root)
        site_entry.pack()

        tk.Label(self.root, text="Password:").pack()
        pw_entry = tk.Entry(self.root)
        pw_entry.pack()

        def store():
            site = site_entry.get()
            pw = pw_entry.get()
            self.manager.password_store[site] = self.manager.encrypt(pw)
            self.manager.save_passwords()
            messagebox.showinfo("Saved", f"Password for '{site}' saved.")
            self.main_menu()

        tk.Button(self.root, text="Save", command=store).pack(pady=10)

    def retrieve_view(self):
        self.clear_window()

        tk.Label(self.root, text="Enter site name:").pack()
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

        tk.Button(self.root, text="Retrieve", command=retrieve).pack(pady=10)

    def clear_window(self):
        for widget in self.root.winfo_children():
            widget.destroy()

# Kör appen
if __name__ == "__main__":
    root = tk.Tk()
    app = PasswordVaultGUI(root)
    root.mainloop()