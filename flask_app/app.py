from flask import Flask, render_template, request, redirect, flash, send_file
from werkzeug.utils import secure_filename
from pathlib import Path
import os
from crypto_utils import generate_keys, encrypt_and_sign_file
from flask import send_file
import io
from crypto_utils import decrypt_and_verify

app = Flask(__name__)
app.secret_key = 'supersecretkey'  # Needed for flashing messages

UPLOAD_DIR = Path(__file__).resolve().parent / "uploads"
UPLOAD_DIR.mkdir(exist_ok=True)

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/generate_keys", methods=["POST"])
def generate_keys_route():
    username = request.form["username"].strip().lower()
    passphrase = request.form["passphrase"]
    confirm = request.form["confirm"]
    if passphrase != confirm:
        flash("Passphrases do not match.")
        return redirect("/")

    try:
        generate_keys(username, passphrase)
        flash(f"[✓] Keys generated for {username}")
    except Exception as e:
        flash(f"[✗] Failed to generate keys: {str(e)}")

    return redirect("/")

@app.route("/send_message", methods=["POST"])
def send_message_route():
    sender = request.form["sender"].strip().lower()
    receiver = request.form["receiver"].strip().lower()
    passphrase = request.form["sender_pass"]
    file = request.files["file"]

    if not file:
        flash("No file selected.")
        return redirect("/")

    filename = secure_filename(file.filename)
    file_data = file.read()

    try:
        encrypt_and_sign_file(sender, receiver, passphrase, file_data, filename)
        flash(f"[✓] File sent securely from {sender} to {receiver}")
    except Exception as e:
        flash(f"[✗] Failed to send file: {str(e)}")

    return redirect("/")

@app.route("/decrypt_message", methods=["POST"])
def decrypt_message_route():
    receiver = request.form["receiver"].strip().lower()
    passphrase = request.form["passphrase"]
    filename = request.form["filename"].strip()

    BASE_DIR = Path(__file__).resolve().parent.parent
    message_path = BASE_DIR / "messages" / f"to_{receiver}" / filename

    try:
        result = decrypt_and_verify(receiver, passphrase, message_path)
        if result["verified"]:
            decrypted_io = io.BytesIO(result["data"])
            decrypted_io.seek(0)
            return send_file(
                decrypted_io,
                as_attachment=True,
                download_name=result["original_filename"],
                mimetype="application/octet-stream"
            )
        else:
            flash("❌ Signature verification failed.")
    except Exception as e:
        flash(f"❌ Error during decryption: {str(e)}")

    return redirect("/")

if __name__ == "__main__":
    app.run(debug=True)
