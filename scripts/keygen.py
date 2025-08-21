from pathlib import Path
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import getpass

def generate_keys(username, passphrase):
    # Create RSA keypair
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()

    user_dir = Path("..") / "users" / username
    user_dir.mkdir(parents=True, exist_ok=True)

    # Save encrypted private key using passphrase
    enc_alg = serialization.BestAvailableEncryption(passphrase.encode())
    priv_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=enc_alg
    )
    with open(user_dir / "private_key.pem", "wb") as f:
        f.write(priv_bytes)

    # Save public key (no encryption)
    pub_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    with open(user_dir / "public_key.pem", "wb") as f:
        f.write(pub_bytes)

    print(f"[✓] Keys generated and protected for user: {username}")

if __name__ == "__main__":
    username = input("Enter username: ").strip().lower()
    passphrase = getpass.getpass("Enter passphrase to protect private key: ")
    confirm = getpass.getpass("Confirm passphrase: ")

    if passphrase != confirm:
        print("[!] Passphrases do not match. Aborting.")
    else:
        generate_keys(username, passphrase)
