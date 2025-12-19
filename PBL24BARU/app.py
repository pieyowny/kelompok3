from flask import Flask, render_template, redirect, url_for, session, flash, send_from_directory
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, FileField, SelectField
from wtforms.validators import DataRequired, Email, ValidationError
import bcrypt
import sqlite3  # Changed from flask_mysqldb
from cryptography.fernet import Fernet
import os
import re

app = Flask(__name__)

# Config
app.secret_key = 'your_secret_key_here'
DB_NAME = 'database.db'

# --- DATABASE SETUP (SQLite) ---
def init_db():
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT NOT NULL UNIQUE,
            password TEXT NOT NULL
        )
    ''')
    conn.commit()
    conn.close()

# Initialize DB immediately
init_db()

# --- VALIDATION FUNCTIONS ---
def validate_username(username):
    if re.search(r"[\'\"-]", username):
        raise ValidationError("Username cannot contain ' \" or -")

def validate_password(password):
    if len(password) < 8:
        raise ValidationError("Password must be at least 8 characters long.")
    if not re.search(r"[0-9]", password):
        raise ValidationError("Password must contain at least one number.")
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        raise ValidationError("Password must contain at least one special character.")

def validate_email_format(email):
    if re.search(r"[\'\"-]", email):
        raise ValidationError("Email cannot contain ' \" or -")

# --- FORMS ---
class RegisterForm(FlaskForm):
    name = StringField("Name", validators=[DataRequired()])
    email = StringField("Email", validators=[DataRequired(), Email()])
    password = PasswordField("Password", validators=[DataRequired()])
    submit = SubmitField("Register")

    def validate_name(self, field):
        validate_username(field.data)

    def validate_password(self, field):
        validate_password(field.data)

    def validate_email(self, field):
        validate_email_format(field.data)
        # Check DB for duplicate email
        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE email=?", (field.data,))
        user = cursor.fetchone()
        conn.close()
        if user:
            raise ValidationError('Email Already Taken')

class LoginForm(FlaskForm):
    email = StringField("Email", validators=[DataRequired(), Email()])
    password = PasswordField("Password", validators=[DataRequired()])
    submit = SubmitField("Login")

class FileForm(FlaskForm):
    file = FileField("File", validators=[DataRequired()])
    # Removed manual key entry to prevent crashes. App will generate it.
    submit = SubmitField("Upload & Encrypt")

class DecryptForm(FlaskForm):
    file_name = SelectField("Select file to decrypt", choices=[], validators=[DataRequired()])
    key = StringField("Decryption Key (Paste from .key file)", validators=[DataRequired()])
    submit = SubmitField("Decrypt")

class TextForm(FlaskForm):
    text = StringField("Text to Encrypt/Decrypt", validators=[DataRequired()])
    key = StringField("Encryption Key", validators=[DataRequired()])
    action = SelectField("Action", choices=[('encrypt', 'Encrypt'), ('decrypt', 'Decrypt')], validators=[DataRequired()])
    submit = SubmitField("Process")

# --- ROUTES ---
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        name = form.name.data
        email = form.email.data
        password = form.password.data

        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        
        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()
        cursor.execute("INSERT INTO users (name, email, password) VALUES (?, ?, ?)", (name, email, hashed_password))
        conn.commit()
        conn.close()

        flash("Registration successful! Please log in.")
        return redirect(url_for('login'))

    return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        email = form.email.data
        password = form.password.data

        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE email=?", (email,))
        user = cursor.fetchone()
        conn.close()
        
        # user[3] is password in our SQLite table structure
        if user and bcrypt.checkpw(password.encode('utf-8'), user[3]):
            session['user_id'] = user[0]
            flash("Login successful!")
            return redirect(url_for('dashboard'))
        else:
            flash("Login failed. Please check your email and password.")
            return redirect(url_for('login'))

    return render_template('login.html', form=form)

@app.route('/dashboard', methods=['GET', 'POST'])
def dashboard():
    if 'user_id' in session:
        user_id = session['user_id']

        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE id=?", (user_id,))
        user = cursor.fetchone()
        conn.close()

        file_form = FileForm()
        decrypt_form = DecryptForm()
        text_form = TextForm()

        uploaded_files = os.listdir('uploads')
        # Filter choices to show only encrypted files (usually we don't decrypt .key files)
        decrypt_form.file_name.choices = [(file, file) for file in uploaded_files if not file.endswith('.key')]

        decrypted_file_path = None
        processed_text = None

        # --- UPLOAD & ENCRYPT ---
        if file_form.validate_on_submit():
            file = file_form.file.data
            file_path = os.path.join('uploads', file.filename)
            file.save(file_path)

            # Generate a VALID key automatically
            key = Fernet.generate_key()
            
            try:
                encrypt_file(file_path, key)

                # Save the key to a file so the user can use it later
                key_file_path = os.path.join('uploads', f"{file.filename}.key")
                with open(key_file_path, 'wb') as key_file:
                    key_file.write(key)

                flash(f"File encrypted! Key saved as '{file.filename}.key'. Download it to decrypt later.")
            except Exception as e:
                flash(f"Encryption failed: {str(e)}")
            return redirect(url_for('dashboard'))

        # --- DECRYPT ---
        if decrypt_form.validate_on_submit():
            file_name = decrypt_form.file_name.data
            file_path = os.path.join('uploads', file_name)
            
            # User must paste the key from the .key file
            key = decrypt_form.key.data.encode() 
            try:
                decrypted_file_path = decrypt_file(file_path, key)
                flash(f"File '{file_name}' has been decrypted.")
            except Exception as e:
                flash(f"Decryption failed: {str(e)}")
                
# --- TEXT ENCRYPTION/DECRYPTION ---
        if text_form.validate_on_submit():
            text = text_form.text.data
            key = text_form.key.data
            action = text_form.action.data

            try:
                # 1. Prepare the key (Fernet requires specific formatting)
                # Ensure key is bytes. NOTE: Fernet keys must be 32 url-safe base64-encoded bytes.
                # If the user types a raw string, this might fail unless it's a valid Fernet key.
                if not key:
                    flash("Please provide a valid encryption key.")
                else:
                    fernet = Fernet(key.encode())

                    # 2. Perform Action
                    if action == 'encrypt':
                        # Encrypt: String -> Bytes -> Encrypt -> Bytes -> String
                        encrypted_bytes = fernet.encrypt(text.encode())
                        processed_text = encrypted_bytes.decode()
                        flash("Text encrypted successfully!")
                    
                    elif action == 'decrypt':
                        # Decrypt: String -> Bytes -> Decrypt -> Bytes -> String
                        decrypted_bytes = fernet.decrypt(text.encode())
                        processed_text = decrypted_bytes.decode()
                        flash("Text decrypted successfully!")

            except Exception as e:
                processed_text = "Error processing text."
                flash(f"Text operation failed: {str(e)}")
        return render_template('dashboard.html', user=user, file_form=file_form, decrypt_form=decrypt_form, text_form=text_form, uploaded_files=uploaded_files, decrypted_file_path=decrypted_file_path, processed_text=processed_text)
    return redirect(url_for('login'))

@app.route('/download/<filename>', methods=['GET'])
def download_file(filename):
    try:
        return send_from_directory('uploads', filename, as_attachment=True)
    except FileNotFoundError:
        flash("File not found!")
        return redirect(url_for('dashboard'))

@app.route('/delete/<filename>', methods=['POST'])
def delete_file(filename):
    try:
        os.remove(os.path.join('uploads', filename))
        flash(f"File '{filename}' has been deleted.")
    except Exception as e:
        flash(f"Error deleting file: {str(e)}")
    return redirect(url_for('dashboard'))

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    flash("You have been logged out successfully.")
    return redirect(url_for('login'))

def encrypt_file(file_path, key):
    fernet = Fernet(key)
    with open(file_path, 'rb') as file:
        original = file.read()
    encrypted = fernet.encrypt(original)
    with open(file_path, 'wb') as encrypted_file:
        encrypted_file.write(encrypted)

def decrypt_file(file_path, key):
    fernet = Fernet(key)
    with open(file_path, 'rb') as encrypted_file:
        encrypted = encrypted_file.read()
        decrypted = fernet.decrypt(encrypted)
    
    decrypted_file_path = file_path.replace('.encrypted', '_decrypted') 
    # Fallback if extension isn't standard
    if decrypted_file_path == file_path:
        decrypted_file_path += "_decrypted"
        
    with open(decrypted_file_path, 'wb') as decrypted_file:
        decrypted_file.write(decrypted)
    
    return os.path.basename(decrypted_file_path) 

if __name__ == '__main__':
    if not os.path.exists('uploads'):
        os.makedirs('uploads')
    app.run(debug=True)