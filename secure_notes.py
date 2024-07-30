import tkinter as tk
from tkinter import messagebox, simpledialog
from cryptography.fernet import Fernet
import os

class SecureNoteApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Secure Note App")

        self.key = self.load_key()
        self.correct_password = "password"  
        self.master_password = "master_password" 
        self.attempts = 0

        self.note_text = tk.Text(self.root, height=10, width=50)
        self.note_text.pack(pady=10)

        encrypt_button = tk.Button(self.root, text="Add Note", command=self.add_note)
        encrypt_button.pack(pady=5)
        view_button = tk.Button(self.root, text="View Notes", command=self.view_notes)
        view_button.pack(pady=5)

        menu_bar = tk.Menu(self.root)
        file_menu = tk.Menu(menu_bar, tearoff=0)
        file_menu.add_command(label="Save Note", command=self.add_note)
        file_menu.add_command(label="Load Note", command=self.view_notes)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=root.quit)
        menu_bar.add_cascade(label="File", menu=file_menu)
        self.root.config(menu=menu_bar)

    def load_key(self):
        key_file = "key.key"
        if os.path.exists(key_file):
            return open(key_file, "rb").read()
        else:
            key = Fernet.generate_key()
            with open(key_file, "wb") as key_file:
                key_file.write(key)
            return key

    def encrypt_message(self, message):
        fernet = Fernet(self.key)
        encrypted = fernet.encrypt(message.encode())
        return encrypted

    def decrypt_message(self, encrypted_message):
        fernet = Fernet(self.key)
        decrypted = fernet.decrypt(encrypted_message).decode()
        return decrypted

    def add_note(self):
        note = self.note_text.get("1.0", tk.END).strip()
        if note:
            encrypted_note = self.encrypt_message(note)
            self.save_to_file(encrypted_note)
            self.note_text.delete("1.0", tk.END)
            messagebox.showinfo("Note Added", "Note added successfully.")
        else:
            messagebox.showwarning("Empty Note", "Note is empty. Please enter some text.")

    def save_to_file(self, encrypted_message):
        with open("notes.txt", "wb") as file:
            file.write(encrypted_message)

    def load_from_file(self):
        try:
            with open("notes.txt", "rb") as file:
                encrypted_message = file.read()
            return encrypted_message
        except FileNotFoundError:
            messagebox.showwarning("No Notes Found", "No notes found.")
            return None

    def view_notes(self):
        if self.attempts >= 3:
            master_password = simpledialog.askstring("Locked", "Enter master password:", show='*')
            if master_password == self.master_password:
                self.attempts = 0
                messagebox.showinfo("Unlocked", "Unlocked successfully.")
            else:
                messagebox.showerror("Error", "Incorrect master password.")
                return

        password = simpledialog.askstring("Password", "Enter your password:", show='*')
        if password == self.correct_password:
            encrypted_note = self.load_from_file()
            if encrypted_note:
                decrypted_note = self.decrypt_message(encrypted_note)
                self.note_text.delete("1.0", tk.END)
                self.note_text.insert("1.0", decrypted_note)
            self.attempts = 0
        else:
            messagebox.showerror("Error", "Incorrect password.")
            self.attempts += 1

if __name__ == "__main__":
    root = tk.Tk()
    app = SecureNoteApp(root)
    root.mainloop()
