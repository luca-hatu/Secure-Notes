from cryptography.fernet import Fernet
import os
import getpass

def load_key():
    key_file = "key.key"
    if os.path.exists(key_file):
        return open(key_file, "rb").read()
    else:
        key = Fernet.generate_key()
        with open(key_file, "wb") as key_file:
            key_file.write(key)
        return key

def encrypt_message(message, key):
    fernet = Fernet(key)
    encrypted = fernet.encrypt(message.encode())
    return encrypted

def decrypt_message(encrypted_message, key):
    fernet = Fernet(key)
    decrypted = fernet.decrypt(encrypted_message).decode()
    return decrypted

def save_to_file(encrypted_message):
    with open("notes.txt", "wb") as file:
        file.write(encrypted_message)

def load_from_file():
    with open("notes.txt", "rb") as file:
        encrypted_message = file.read()
    return encrypted_message

def check_password(password, correct_password):
    return password == correct_password

def main():
    key = load_key()
    correct_password = "reese" 
    master_password = "master_password" 
    attempts = 0

    while True:
        print("\n1. Add a note")
        print("2. View notes")
        print("3. Exit")
        choice = input("Enter your choice: ")

        if choice == "1":
            note = input("Enter your note: ")
            encrypted_note = encrypt_message(note, key)
            save_to_file(encrypted_note)
            print("Note added successfully.")

        elif choice == "2":
            if attempts >= 3:
                print("Notes are locked. Enter master password to unlock.")
                password = getpass.getpass("Enter master password: ")
                if check_password(password, master_password):
                    attempts = 0
                    print("Unlocked successfully.")
                else:
                    print("Incorrect master password.")
                    continue

            password = getpass.getpass("Enter your password: ")
            if check_password(password, correct_password):
                try:
                    encrypted_note = load_from_file()
                    decrypted_note = decrypt_message(encrypted_note, key)
                    print(f"\nYour notes: {decrypted_note}")
                except FileNotFoundError:
                    print("No notes found.")
                attempts = 0
            else:
                print("Incorrect password.")
                attempts += 1

        elif choice == "3":
            break

        else:
            print("Invalid choice. Please enter 1, 2, or 3.")

if __name__ == "__main__":
    main()
