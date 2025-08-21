import os
import json
import getpass
from pathlib import Path
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding, rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sym_padding
from cryptography.hazmat.backends import default_backend

def load_key(path, is_private=False, passphrase=None):
    with open(path, "rb") as f:
        key_data = f.read()
        if is_private:
            if passphrase is None:
                passphrase = getpass.getpass("Enter passphrase for sender's private key: ")
            return serialization.load_pem_private_key(key_data, password=passphrase.encode())
        else:
            return serialization.load_pem_public_key(key_data)

def encrypt_file(data, aes_key, iv):
    padder = sym_padding.PKCS7(128).padder()
    padded = padder.update(data) + padder.finalize()
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    return encryptor.update(padded) + encryptor.finalize()

def encrypt_key(aes_key, receiver_pub):
    return receiver_pub.encrypt(
        aes_key,
        asym_padding.OAEP(mgf=asym_padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )

def sign_data(data, sender_priv):
    digest = hashes.Hash(hashes.SHA256())
    digest.update(data)
    return sender_priv.sign(
        digest.finalize(),
        asym_padding.PSS(
            mgf=asym_padding.MGF1(hashes.SHA256()),
            salt_length=asym_padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

def send_message(sender, receiver, input_file):
    sender_dir = Path("..") / "users" / sender
    receiver_dir = Path("..") / "users" / receiver
    msg_dir = Path("..") / "messages" / f"to_{receiver}"
    msg_dir.mkdir(parents=True, exist_ok=True)

    # Load sender private key (prompt for passphrase)
    sender_priv = load_key(sender_dir / "private_key.pem", is_private=True)

    # Load receiver public key
    receiver_pub = load_key(receiver_dir / "public_key.pem")

    # Read and encrypt file
    with open(input_file, "rb") as f:
        data = f.read()

    import secrets
    aes_key = secrets.token_bytes(32)
    iv = secrets.token_bytes(16)
    encrypted_data = encrypt_file(data, aes_key, iv)

    # Encrypt AES key with receiver's RSA
    encrypted_key = encrypt_key(aes_key, receiver_pub)

    # Sign data with sender's private key
    signature = sign_data(data, sender_priv)

    # Save everything
    import time
    ts = str(int(time.time()))
    filename = Path(input_file).name
    prefix = f"{sender}_to_{receiver}_{ts}"

    with open(msg_dir / f"{prefix}_encrypted_file.bin", "wb") as f:
        f.write(encrypted_data)

    with open(msg_dir / f"{prefix}_encrypted_key.bin", "wb") as f:
        f.write(encrypted_key)

    with open(msg_dir / f"{prefix}_signature.bin", "wb") as f:
        f.write(signature)

    metadata = {
        "sender": sender,
        "original_filename": filename,
        "iv": iv.hex()
    }
    with open(msg_dir / f"{prefix}_metadata.json", "w") as f:
        json.dump(metadata, f)

    print(f"[✓] Encrypted message sent from {sender} to {receiver}")

if __name__ == "__main__":
    sender = input("Sender username: ").strip().lower()
    receiver = input("Receiver username: ").strip().lower()
    input_file = input("Path to file to send: ").strip()
    send_message(sender, receiver, input_file)
