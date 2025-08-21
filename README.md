# Secure File Messaging System (Hybrid Encryption + Digital Signatures)

A secure file transfer platform that uses **RSA + AES hybrid encryption** and **RSA-PSS digital signatures** to protect files during exchange.  
The project supports both a **Flask web interface** and **command-line utilities** for sending, receiving, and decrypting files.

---

## Features

- **User key generation (RSA 2048-bit)** with passphrase protection.
- **Hybrid encryption** (AES-256-CBC for files, RSA-OAEP for key exchange).
- **Digital signatures** (RSA-PSS with SHA-256) to ensure authenticity.
- **Web interface (Flask)** for:
  - Key creation  
  - Secure file sending  
  - Secure file decryption  
- **CLI tools** for manual encryption, sending, and receiving.
- **Message inbox** for storing and verifying received files.

---

## Project Structure

├── app.py # Flask web app (GUI)
├── crypto_utils.py # Core cryptography logic
├── keygen.py # Standalone key generation script
├── send_message.py # Standalone secure sender (CLI)
├── receive_message.py # Standalone secure receiver (CLI)
├── users/ # Auto-created: stores keys and inboxes
└── messages/ # Auto-created: stores encrypted messages


---

## How It Works

1. **Key Generation**  
   - Each user generates an RSA key pair using a passphrase.  
   - The private key is encrypted locally and stored safely.  
   - Public keys are unencrypted and shared automatically.

2. **Sending a File**  
   - A random AES-256 key encrypts the file.  
   - This AES key is encrypted with the receiver’s RSA public key (RSA-OAEP).  
   - The file is digitally signed with the sender’s private key (RSA-PSS).  
   - All files, keys, IVs, and signatures are saved in `messages/to_<receiver>/`.

3. **Receiving and Decrypting a File**  
   - The receiver unlocks their private key using a passphrase.  
   - The AES key is decrypted using RSA.  
   - The file is decrypted with AES and its signature verified using the sender’s public key.  
   - Verified files are saved in the receiver's inbox.

---

## Installation

1. **Clone the repository**  
```bash
git clone https://github.com/your-username/secure-file-messaging.git
cd secure-file-messaging

Install dependencies
pip install flask cryptography

Run the Flask app
python app.py

Open http://127.0.0.1:5000
 in your browser.
