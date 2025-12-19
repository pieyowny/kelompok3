from flask import Flask, render_template, redirect, url_for, flash
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, SelectField
from wtforms.validators import DataRequired
from cryptography.fernet import Fernet, InvalidToken
import base64
import binascii

app = Flask(__name__)

# Config
app.secret_key = 'your_secret_key_here'

# This application is a standalone text encryption/decryption tool (Fernet supported).

class TextForm(FlaskForm):
    text = StringField("Text to Encrypt/Decrypt", validators=[DataRequired()])
    key = StringField("Encryption Key", validators=[DataRequired()])
    action = SelectField("Action", choices=[('encrypt', 'Encrypt'), ('decrypt', 'Decrypt')], validators=[DataRequired()])
    submit = SubmitField("Process")

# --- ROUTES ---
@app.route('/')
def index():
    # Redirect to the dashboard so the app opens directly to the main encryption/decryption page
    return redirect(url_for('dashboard'))


# ...existing code...
@app.route('/dashboard', methods=['GET', 'POST'])
def dashboard():
    # Standalone text encryption/decryption tool
    text_form = TextForm()
    processed_text = None

    # Server-side Fernet-based text encrypt/decrypt (optional)
    if text_form.validate_on_submit():
        raw_text = (text_form.text.data or "").strip()
        key_str = (text_form.key.data or "").strip()
        action = text_form.action.data

        # Validate key: must be URL-safe base64 that decodes to 32 bytes
        try:
            decoded = base64.urlsafe_b64decode(key_str)
            if len(decoded) != 32:
                flash("Invalid encryption key length. Key must decode to 32 bytes (use Fernet.generate_key()).")
            else:
                fernet = Fernet(key_str.encode())

                try:
                    if action == 'encrypt':
                        encrypted_bytes = fernet.encrypt(raw_text.encode('utf-8'))
                        processed_text = encrypted_bytes.decode('utf-8')
                        flash("Text encrypted successfully.")
                    elif action == 'decrypt':
                        # ciphertext may contain whitespace — strip it
                        decrypted_bytes = fernet.decrypt(raw_text.encode('utf-8'))
                        processed_text = decrypted_bytes.decode('utf-8')
                        flash("Text decrypted successfully.")
                except InvalidToken:
                    processed_text = None
                    flash("Failed to decrypt: invalid key or corrupted ciphertext.")
        except (binascii.Error, ValueError):
            processed_text = None
            flash("Invalid encryption key format. Key must be a URL-safe Base64-encoded 32-byte key.")
        except Exception as e:
            processed_text = None
            flash(f"Text operation failed: {str(e)}")

    return render_template('dashboard.html', text_form=text_form, processed_text=processed_text)



if __name__ == '__main__':
    app.run(debug=True)