import os
import json
import getpass
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import utils as asym_utils
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sym_padding
from cryptography.hazmat.backends import default_backend

def load_private_key(path, passphrase):
    with open(path, "rb") as f:
        key_data = f.read()
        return serialization.load_pem_private_key(key_data, password=passphrase.encode())

def load_public_key(path):
    with open(path, "rb") as f:
        return serialization.load_pem_public_key(f.read())

def decrypt_aes_key(encrypted_key, private_key):
    return private_key.decrypt(
        encrypted_key,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )

def decrypt_file(data, aes_key, iv):
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded = decryptor.update(data) + decryptor.finalize()
    unpadder = sym_padding.PKCS7(128).unpadder()
    return unpadder.update(padded) + unpadder.finalize()

def verify_signature(data, signature, sender_pub):
    digest = hashes.Hash(hashes.SHA256())
    digest.update(data)
    try:
        sender_pub.verify(
            signature,
            digest.finalize(),
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            asym_utils.Prehashed(hashes.SHA256())
        )
        return True
    except Exception:
        return False

def process_messages(receiver, passphrase):
    base = Path("..")
    msg_dir = base / "messages" / f"to_{receiver}"
    recv_dir = base / "users" / receiver
    inbox = recv_dir / "inbox"
    inbox.mkdir(exist_ok=True)

    priv_path = recv_dir / "private_key.pem"
    receiver_priv = load_private_key(priv_path, passphrase)

    for file in msg_dir.glob("*_metadata.json"):
        prefix = file.stem.replace("_metadata", "")
        metadata = json.loads(file.read_text())
        sender = metadata["sender"]
        iv = bytes.fromhex(metadata["iv"])
        original_name = metadata["original_filename"]

        sender_pub = load_public_key(base / "users" / sender / "public_key.pem")

        with open(msg_dir / f"{prefix}_encrypted_key.bin", "rb") as f:
            encrypted_key = f.read()

        with open(msg_dir / f"{prefix}_encrypted_file.bin", "rb") as f:
            enc_file = f.read()

        with open(msg_dir / f"{prefix}_signature.bin", "rb") as f:
            signature = f.read()

        try:
            aes_key = decrypt_aes_key(encrypted_key, receiver_priv)
            decrypted_data = decrypt_file(enc_file, aes_key, iv)
            is_valid = verify_signature(decrypted_data, signature, sender_pub)

            if is_valid:
                output_file = inbox / f"{prefix}_{original_name}"
                with open(output_file, "wb") as out:
                    out.write(decrypted_data)
                print(f"[✓] Verified message from {sender} → saved to inbox: {output_file.name}")
            else:
                print(f"[!] Invalid signature on message from {sender}")
        except Exception as e:
            print(f"[✗] Error processing {prefix}: {e}")

if __name__ == "__main__":
    receiver = input("Receiver username: ").strip().lower()
    passphrase = getpass.getpass("Enter passphrase to unlock your private key: ")
    process_messages(receiver, passphrase)
