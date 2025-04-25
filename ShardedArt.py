import tkinter as tk
from tkinter import filedialog, messagebox
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os
from secretsharing import SecretSharer
import hashlib

# Hardcoded credentials
ADMIN_CREDS = {"username": "admin", "password": "admin123"}
USER_CREDS = {"username": "user", "password": "user123"}

# Global variables
generated_key = None
key_shares = []
original_image_hash = None
original_image_path = None

# Login Window
def show_login():
    login_window = tk.Tk()
    login_window.title("ShardedArt - Login")
    login_window.geometry("350x250")
    login_window.configure(bg="#4A4A4A")

    tk.Label(login_window, text="ShardedArt Login", font=("Helvetica", 16, "bold"), bg="#4A4A4A", fg="#ffffff").pack(pady=20)
    tk.Label(login_window, text="Username", font=("Helvetica", 12), bg="#4A4A4A", fg="#ffffff").pack(pady=5)
    username_entry = tk.Entry(login_window, font=("Helvetica", 12), width=25, bg="#ffffff", fg="#000000", borderwidth=2, relief="flat", highlightthickness=1, highlightcolor="#6A0DAD")
    username_entry.pack(pady=5)

    tk.Label(login_window, text="Password", font=("Helvetica", 12), bg="#4A4A4A", fg="#ffffff").pack(pady=5)
    password_entry = tk.Entry(login_window, show="*", font=("Helvetica", 12), width=25, bg="#ffffff", fg="#0000FF", borderwidth=2, relief="flat", highlightthickness=1, highlightcolor="#6A0DAD")
    password_entry.pack(pady=5)

    def validate_login():
        username = username_entry.get()
        password = password_entry.get()
        if username == ADMIN_CREDS["username"] and password == ADMIN_CREDS["password"]:
            login_window.destroy()
            show_admin_module()
        elif username == USER_CREDS["username"] and password == USER_CREDS["password"]:
            login_window.destroy()
            show_user_module()
        else:
            messagebox.showerror("Error", "Invalid credentials")

    tk.Button(login_window, text="Login", command=validate_login, font=("Helvetica", 12), bg="#000000", fg="#0000FF", width=15, borderwidth=0, activebackground="#333333").pack(pady=20)
    login_window.mainloop()

# Admin Module
def show_admin_module():
    global generated_key, key_shares, original_image_hash, original_image_path
    admin_window = tk.Tk()
    admin_window.title("ShardedArt - Admin Module")
    admin_window.geometry("450x500")
    admin_window.configure(bg="#4A4A4A")

    tk.Label(admin_window, text="Admin Module", font=("Helvetica", 16, "bold"), bg="#4A4A4A", fg="#ffffff").pack(pady=20)
    status_label = tk.Label(admin_window, text="", font=("Helvetica", 10), bg="#4A4A4A", fg="#ff4500")
    status_label.pack(pady=5)

    def generate_and_split_key():
        global generated_key, key_shares
        status_label.config(text="Generating key...")
        admin_window.update()
        generated_key = os.urandom(32)
        key_hex = generated_key.hex()
        print(f"Generated key (hex): {key_hex}")
        key_shares = SecretSharer.split_secret(key_hex, 3, 5)
        shares_text = "\n".join(key_shares)
        messagebox.showinfo("Success", f"Key generated and split into 5 shares (3 required):\n{shares_text}\nSave these shares!")
        status_label.config(text="Key generated!")

    def save_shares_to_file():
        if not key_shares:
            messagebox.showerror("Error", "Generate shares first!")
            return
        save_path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text files", "*.txt")])
        if save_path:
            with open(save_path, 'w') as f:
                f.write("\n".join(key_shares))
            messagebox.showinfo("Success", f"Shares saved to {save_path}")

    def encrypt_image():
        global generated_key, original_image_hash, original_image_path
        if generated_key is None:
            messagebox.showerror("Error", "Generate and split a key first!")
            return
        status_label.config(text="Encrypting image...")
        admin_window.update()
        print("Opening file dialog for image selection...")
        image_path = filedialog.askopenfilename(filetypes=[
            ("PNG files", "*.png"),
            ("JPEG files", "*.jpg"),
            ("JPEG files", "*.jpeg")
        ])
        print(f"Selected path: {image_path}")
        if not image_path:
            status_label.config(text="No file selected")
            return
        if not image_path.lower().endswith(('.png', '.jpg', '.jpeg')):
            messagebox.showerror("Error", "Please select a .png, .jpg, or .jpeg file!")
            status_label.config(text="Invalid file type")
            return
        with open(image_path, 'rb') as f:
            image_data = f.read()
        original_image_path = image_path
        original_image_hash = hashlib.sha256(image_data).hexdigest()
        print(f"Original image hash: {original_image_hash}")
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(generated_key), modes.CTR(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        encrypted_data = encryptor.update(image_data) + encryptor.finalize()
        print("Opening save dialog...")
        save_path = filedialog.asksaveasfilename(defaultextension=".bin", filetypes=[("Binary files", "*.bin")])
        print(f"Save path: {save_path}")
        if save_path:
            with open(save_path, 'wb') as f:
                f.write(iv + encrypted_data)
            messagebox.showinfo("Success", "Image encrypted and saved!")
            status_label.config(text="Encryption complete!")
        else:
            status_label.config(text="Save cancelled")

    tk.Button(admin_window, text="Generate and Split Key", command=generate_and_split_key, font=("Helvetica", 12), bg="#000000", fg="#0000FF", width=20, borderwidth=0, activebackground="#333333").pack(pady=20)
    tk.Button(admin_window, text="Save Shares to File", command=save_shares_to_file, font=("Helvetica", 12), bg="#000000", fg="#0000FF", width=20, borderwidth=0, activebackground="#333333").pack(pady=20)
    tk.Button(admin_window, text="Upload Image and Encrypt", command=encrypt_image, font=("Helvetica", 12), bg="#000000", fg="#0000FF", width=20, borderwidth=0, activebackground="#333333").pack(pady=20)
    tk.Button(admin_window, text="Logout", command=admin_window.destroy, font=("Helvetica", 12), bg="#000000", fg="#0000FF", width=20, borderwidth=0, activebackground="#333333").pack(pady=20)

    admin_window.mainloop()

# User Module
def show_user_module():
    global original_image_hash, original_image_path
    user_window = tk.Tk()
    user_window.title("ShardedArt - User Module")
    user_window.geometry("450x600")
    user_window.configure(bg="#4A4A4A")

    tk.Label(user_window, text="User Module", font=("Helvetica", 16, "bold"), bg="#4A4A4A", fg="#ffffff").pack(pady=20)
    tk.Label(user_window, text="Enter 3 shares below:", font=("Helvetica", 12), bg="#4A4A4A", fg="#ffffff").pack(pady=10)
    status_label = tk.Label(user_window, text="", font=("Helvetica", 10), bg="#4A4A4A", fg="#ff4500")
    status_label.pack(pady=5)

    share_entries = []
    for i in range(3):
        frame = tk.Frame(user_window, bg="#4A4A4A")
        frame.pack(pady=5)
        tk.Label(frame, text=f"Share {i+1}:", font=("Helvetica", 12), bg="#4A4A4A", fg="#ffffff").pack(side=tk.LEFT, padx=5)
        entry = tk.Entry(frame, font=("Helvetica", 12), width=35, bg="#ffffff", fg="#000000", borderwidth=2, relief="flat", highlightthickness=1, highlightcolor="#6A0DAD")
        entry.pack(side=tk.LEFT)
        share_entries.append(entry)

    def decrypt_image():
        global original_image_hash, original_image_path
        print("Opening file dialog for encrypted file...")
        encrypted_path = filedialog.askopenfilename(filetypes=[("Binary files", "*.bin")])
        print(f"Selected encrypted path: {encrypted_path}")
        if not encrypted_path:
            status_label.config(text="No file selected")
            return
        shares_input = [entry.get().strip() for entry in share_entries if entry.get().strip()]
        if len(shares_input) < 3:
            messagebox.showerror("Error", "At least 3 shares are required!")
            return
        status_label.config(text="Validating shares...")
        user_window.update()
        valid_shares = []
        for share in shares_input:
            try:
                index, value = share.split('-', 1)
                int(index)
                bytes.fromhex(value)
                valid_shares.append(share)
            except ValueError:
                messagebox.showerror("Error", f"Invalid share format: '{share}'. Use 'index-value' (e.g., 1-abc...)")
                return
        if len(valid_shares) < 3:
            messagebox.showerror("Error", "Fewer than 3 valid shares provided!")
            return
        status_label.config(text="Reconstructing key...")
        user_window.update()
        try:
            reconstructed_key_hex = SecretSharer.recover_secret(valid_shares[:3])
            reconstructed_key = bytes.fromhex(reconstructed_key_hex)
            print(f"Reconstructed key (hex): {reconstructed_key_hex}")
            if len(reconstructed_key) != 32:
                raise ValueError("Reconstructed key is invalid")
        except Exception as e:
            messagebox.showerror("Error", f"Invalid shares or reconstruction failed: {str(e)}")
            return
        status_label.config(text="Decrypting image...")
        user_window.update()
        with open(encrypted_path, 'rb') as f:
            data = f.read()
        iv = data[:16]
        encrypted_data = data[16:]
        cipher = Cipher(algorithms.AES(reconstructed_key), modes.CTR(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()
        decrypted_hash = hashlib.sha256(decrypted_data).hexdigest()
        print(f"Decrypted image hash: {decrypted_hash}")
        if original_image_hash and decrypted_hash != original_image_hash:
            print(f"Hash mismatch! Original: {original_image_hash}, Decrypted: {decrypted_hash}")
            messagebox.showwarning("Warning", "Decrypted image may be corrupted (hash mismatch)!")
        print("Opening save dialog for decrypted image...")
        default_ext = os.path.splitext(original_image_path)[1] if original_image_path else ".png"
        save_path = filedialog.asksaveasfilename(defaultextension=default_ext, filetypes=[
            ("PNG files", "*.png"),
            ("JPEG files", "*.jpg"),
            ("JPEG files", "*.jpeg")
        ])
        print(f"Save path: {save_path}")
        if save_path:
            with open(save_path, 'wb') as f:
                f.write(decrypted_data)
            messagebox.showinfo("Success", "Image decrypted and saved!")
            status_label.config(text="Decryption complete!")
        else:
            status_label.config(text="Save cancelled")

    

    tk.Button(user_window, text="Decrypt and Download", command=decrypt_image, font=("Helvetica", 12), bg="#000000", fg="#0000FF", width=20, borderwidth=0, activebackground="#333333").pack(pady=20)
    tk.Button(user_window, text="Logout", command=user_window.destroy, font=("Helvetica", 12), bg="#000000", fg="#0000FF", width=20, borderwidth=0, activebackground="#333333").pack(pady=20)

    user_window.mainloop()

# Start the application
if __name__ == "__main__":
    show_login()