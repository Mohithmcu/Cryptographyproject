from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sym_padding
from cryptography.hazmat.backends import default_backend
from pathlib import Path
import os, json

BASE_DIR = Path(__file__).resolve().parent.parent

def generate_keys(username, passphrase):
    user_dir = BASE_DIR / "users" / username
    os.makedirs(user_dir, exist_ok=True)

    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    encrypted_private_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.BestAvailableEncryption(passphrase.encode())
    )
    public_bytes = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    with open(user_dir / "private_key.pem", "wb") as f:
        f.write(encrypted_private_bytes)
    with open(user_dir / "public_key.pem", "wb") as f:
        f.write(public_bytes)

def load_private_key(username, passphrase):
    path = BASE_DIR / "users" / username / "private_key.pem"
    with open(path, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=passphrase.encode())

def load_public_key(username):
    path = BASE_DIR / "users" / username / "public_key.pem"
    with open(path, "rb") as f:
        return serialization.load_pem_public_key(f.read())

def encrypt_and_sign_file(sender, receiver, passphrase, file_data, filename):
    sender_priv = load_private_key(sender, passphrase)
    receiver_pub = load_public_key(receiver)

    # Symmetric encryption
    key = os.urandom(32)
    iv = os.urandom(16)
    padder = sym_padding.PKCS7(128).padder()
    padded_data = padder.update(file_data) + padder.finalize()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encrypted_data = cipher.encryptor().update(padded_data) + cipher.encryptor().finalize()

    # Encrypt AES key using RSA
    encrypted_key = receiver_pub.encrypt(
        key,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )

    # Sign original data
    signature = sender_priv.sign(
        file_data,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256()
    )

    # Save to /messages
    msg_dir = BASE_DIR / "messages" / f"to_{receiver}"
    msg_dir.mkdir(parents=True, exist_ok=True)
    prefix = f"{sender}_to_{receiver}_{int(os.times()[4])}"
    with open(msg_dir / f"{prefix}_file.bin", "wb") as f:
        f.write(encrypted_data)
    with open(msg_dir / f"{prefix}_key.bin", "wb") as f:
        f.write(encrypted_key)
    with open(msg_dir / f"{prefix}_iv.bin", "wb") as f:
        f.write(iv)
    with open(msg_dir / f"{prefix}_signature.bin", "wb") as f:
        f.write(signature)
    with open(msg_dir / f"{prefix}_meta.json", "w") as f:
        json.dump({"filename": filename}, f)
def decrypt_and_verify(receiver, passphrase, message_file: Path):
    from cryptography.hazmat.primitives.asymmetric import padding as asym_padding

    # Extract file components based on how they were actually saved
    prefix = "_".join(message_file.stem.split("_")[:-1])
    folder = message_file.parent

    enc_file = folder / f"{prefix}_file.bin"
    enc_key = folder / f"{prefix}_key.bin"
    iv_file = folder / f"{prefix}_iv.bin"
    sig_file = folder / f"{prefix}_signature.bin"
    meta_file = folder / f"{prefix}_meta.json"

    # Load metadata
    with open(meta_file, "r") as f:
        metadata = json.load(f)

    original_filename = metadata["filename"]
    sender = prefix.split("_to_")[0]

    # Load keys
    receiver_priv = load_private_key(receiver, passphrase)
    sender_pub = load_public_key(sender)

    # Load encrypted key & decrypt
    with open(enc_key, "rb") as f:
        encrypted_key = f.read()
    aes_key = receiver_priv.decrypt(
        encrypted_key,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # Decrypt file
    with open(iv_file, "rb") as f:
        iv = f.read()
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded = decryptor.update(enc_file.read_bytes()) + decryptor.finalize()
    unpadder = sym_padding.PKCS7(128).unpadder()
    decrypted_data = unpadder.update(padded) + unpadder.finalize()

    # Verify signature
    with open(sig_file, "rb") as f:
        signature = f.read()
    verified = sender_pub.verify(
        signature,
        decrypted_data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    ) is None  # If verify() succeeds, no exception

    return {
        "verified": True,
        "data": decrypted_data,
        "original_filename": original_filename,
        "sender": sender
    }
