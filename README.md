# Crypto_ShardedArtProject
Secure image encryption and decryption using AES and Shamir’s Secret Sharing in Python


ShardedArt

ShardedArt is a Python application designed for secure image encryption and decryption using AES (Advanced Encryption Standard) and Shamir's Secret Sharing. The application provides a user-friendly graphical user interface (GUI) built with Tkinter, allowing users to encrypt images and distribute the encryption key as shares among multiple parties. A minimum number of shares are required to reconstruct the key and decrypt the image, ensuring secure and controlled access.

Features





Secure Encryption: Encrypts images (PNG, JPEG) using AES-256 in CTR mode for robust security.



Distributed Key Management: Splits the encryption key into 5 shares using Shamir's Secret Sharing, requiring at least 3 shares to reconstruct the key.



User Roles:





Admin: Generates keys, splits them into shares, and encrypts images.



User: Reconstructs the key from shares and decrypts images.



Tkinter GUI: Intuitive interface with distinct modules for Admin and User workflows.



Data Integrity: Uses SHA-256 hashing to verify that decrypted images match the originals.



Test Image: Includes test_image.png for testing encryption and decryption workflows.

Requirements

To run ShardedArt, you’ll need the following:





Python: Version 3.12 or higher



Libraries:





tkinter: For the GUI (usually included with Python).



cryptography: For AES encryption.



secretsharing: For Shamir's Secret Sharing implementation.



Operating System: Tested on macOS, but should work on Windows and Linux with minor adjustments.

Installation





Clone the Repository:

git clone https://github.com/your-username/ShardedArt.git
cd ShardedArt



Set Up a Virtual Environment (optional but recommended):

python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate



Install Dependencies: Install the required Python libraries using pip:

pip install cryptography secretsharing





tkinter is typically included with Python. If it’s missing, you may need to install it separately (e.g., on Linux: sudo apt-get install python3-tk).

Usage





Run the Application:

python ShardedArt.py



Login:





Admin: Use credentials admin / admin123





Generate and split an encryption key into 5 shares (3 required to reconstruct).



Save the shares to a .txt file.



Upload an image (PNG or JPEG) to encrypt and save as a .bin file.



User: Use credentials user / user123





Enter 3 shares to reconstruct the key.



Upload the encrypted .bin file to decrypt and save the image in its original format.



Test with the Provided Image:





The repository includes test_image.png, which you can use to test the encryption and decryption process.

Project Structure





ShardedArt.py: The main application script containing the GUI and encryption/decryption logic.



test_image.png: A sample image for testing the application.



.gitignore: Ignores generated files like .bin (encrypted files) and .txt (share files).

UI Design





Background: Medium-dark grey (#4A4A4A) for better contrast.



Buttons: Black (#000000) with white text, no active state change on click.



Labels: White text (#ffffff) on the grey background for readability (contrast ratio 7.6:1).



Status Messages: Orange (#ff4500) for visibility (contrast ratio 8.2:1).

Test Image





test_image.png: A sample image included in the repository for testing purposes.



Use this image to test the encryption and decryption workflows without needing to provide your own image.

Contributing

Contributions are welcome! To contribute:





Fork the repository.



Create a new branch for your feature or bug fix:

git checkout -b feature-name



Make your changes and commit them:

git commit -m "Add feature description"



Push to your fork:

git push origin feature-name



Open a pull request on GitHub.
