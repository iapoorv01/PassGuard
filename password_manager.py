import sys
from PyQt6.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
                             QPushButton, QLineEdit, QLabel, QFrame, QListWidget, QListWidgetItem, QComboBox)
from PyQt6.QtCore import Qt, QEvent, QMargins, QUrl, QTimer
from PyQt6.QtGui import QPalette, QColor, QFont, QClipboard, QDesktopServices
from firebase_admin import credentials, firestore, initialize_app
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Protocol.KDF import scrypt
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
import base64
import random
import string
import re
import cv2
import face_recognition
import psutil
import uuid

# Initialize Firebase
cred = credentials.Certificate("password_manager.json")
initialize_app(cred)
db = firestore.client()
users_ref = db.collection("users")
credentials_ref = db.collection("credentials")

# Encryption/Decryption Functions
def encrypt_with_key(data, key):
    salt = get_random_bytes(16)
    derived_key = scrypt(key.encode() if isinstance(key, str) else key, salt, 32, N=2**14, r=8, p=1)
    cipher = AES.new(derived_key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(data)
    return base64.b64encode(salt + cipher.nonce + tag + ciphertext).decode()

def decrypt_with_key(encrypted_data, key):
    try:
        data = base64.b64decode(encrypted_data)
        salt, iv, tag, ciphertext = data[:16], data[16:32], data[32:48], data[48:]
        derived_key = scrypt(key.encode() if isinstance(key, str) else key, salt, 32, N=2**14, r=8, p=1)
        cipher = AES.new(derived_key, AES.MODE_GCM, nonce=iv)
        return cipher.decrypt_and_verify(ciphertext, tag)
    except ValueError as e:
        print(f"Decryption failed: {e}")
        return None

def encrypt_password(password, master_password, public_key):
    salt = get_random_bytes(16)
    key = scrypt(master_password.encode(), salt, 32, N=2**14, r=8, p=1)
    cipher = AES.new(key, AES.MODE_GCM)
    encrypted_password, tag = cipher.encrypt_and_digest(password.encode())
    rsa_cipher = PKCS1_OAEP.new(RSA.import_key(public_key))
    encrypted_key = rsa_cipher.encrypt(key)
    return {
        "salt": base64.b64encode(salt).decode(),
        "nonce": base64.b64encode(cipher.nonce).decode(),
        "tag": base64.b64encode(tag).decode(),
        "encrypted_password": base64.b64encode(encrypted_password).decode(),
        "encrypted_key": base64.b64encode(encrypted_key).decode()
    }

def decrypt_password(encrypted_data, master_password, private_key):
    salt = base64.b64decode(encrypted_data["salt"])
    nonce = base64.b64decode(encrypted_data["nonce"])
    tag = base64.b64decode(encrypted_data["tag"])
    encrypted_password = base64.b64decode(encrypted_data["encrypted_password"])
    encrypted_key = base64.b64decode(encrypted_data["encrypted_key"])
    rsa_cipher = PKCS1_OAEP.new(RSA.import_key(private_key))
    key = rsa_cipher.decrypt(encrypted_key)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    return cipher.decrypt_and_verify(encrypted_password, tag).decode()

def generate_and_store_keys(user_id, master_password, face_encoding=None, device_id=None, trusted_contact_id=None):
    key = RSA.generate(1024)  # Use 4096 in production
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    encrypted_private_key = encrypt_with_key(private_key, master_password)

    user_data = {
        "public_key": public_key.decode(),
        "encrypted_private_key": encrypted_private_key
    }
    if face_encoding is not None:
        face_key = base64.b64encode(face_encoding).decode()
        user_data["face_recovery_key"] = encrypt_with_key(private_key, face_key)
        user_data["face_encoding"] = base64.b64encode(face_encoding).decode()
    if device_id is not None:
        user_data["device_recovery_key"] = encrypt_with_key(private_key, device_id)
    if trusted_contact_id:
        contact_doc = users_ref.document(trusted_contact_id).get()
        if contact_doc.exists:
            contact_public_key = contact_doc.to_dict()["public_key"]
            user_data["contact_recovery_key"] = encrypt_with_key(private_key, contact_public_key)
            user_data["trusted_contact_id"] = trusted_contact_id

    users_ref.document(user_id).set(user_data)
    return public_key, private_key

# Password Generator and Strength Checker
def generate_password(length=16):
    characters = string.ascii_letters + string.digits + string.punctuation
    return ''.join(random.choice(characters) for _ in range(length))

def check_password_strength(password):
    length = len(password)
    has_upper = bool(re.search(r'[A-Z]', password))
    has_lower = bool(re.search(r'[a-z]', password))
    has_digit = bool(re.search(r'\d', password))
    has_special = bool(re.search(r'[!@#$%^&*(),.?":{}|<>]', password))

    score = 0
    if length >= 8: score += 1
    if length >= 12: score += 1
    if has_upper: score += 1
    if has_lower: score += 1
    if has_digit: score += 1
    if has_special: score += 1

    if score <= 2: return "Weak", "#FF6B6B"
    elif score <= 4: return "Medium", "#FFD166"
    else: return "Strong", "#10B981"

# Main Window
class PasswordManagerWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Secure Password Manager")
        self.setGeometry(100, 100, 1000, 700)
        self.is_dark_mode = False

        central_widget = QWidget(self)
        self.setCentralWidget(central_widget)
        main_layout = QHBoxLayout(central_widget)
        main_layout.setContentsMargins(0, 0, 0, 0)

        # Sidebar
        sidebar = QFrame()
        sidebar.setFixedWidth(250)
        sidebar.setStyleSheet("background: #4A90E2; border-radius: 10px;")
        sidebar_layout = QVBoxLayout(sidebar)
        sidebar_layout.setContentsMargins(15, 30, 15, 30)
        logo = QLabel("🔒 PassGuard")
        logo.setFont(QFont("Montserrat", 22, QFont.Weight.Bold))
        logo.setStyleSheet("color: white;")
        sidebar_layout.addWidget(logo, alignment=Qt.AlignmentFlag.AlignCenter)

        self.sidebar_buttons = {}
        for text, cmd in [("Add Credential", self.show_add_credential),
                          ("View Credentials", self.show_view_credentials),
                          ("Settings", self.show_settings)]:
            btn = QPushButton(text)
            btn.setFont(QFont("Montserrat", 14))
            btn.setStyleSheet("""
                QPushButton { 
                    background: transparent; 
                    color: white; 
                    padding: 12px; 
                    border-radius: 8px; 
                    text-align: left;
                }
                QPushButton:hover { background: rgba(255, 255, 255, 0.2); }
                QPushButton:disabled { color: #A0A0A0; }
            """)
            btn.clicked.connect(lambda checked, c=cmd: self.check_login_before_action(c))
            btn.setEnabled(False)
            self.sidebar_buttons[text] = btn
            sidebar_layout.addWidget(btn)
        sidebar_layout.addStretch()

        # Content area
        self.content = QFrame()
        self.content_layout = QVBoxLayout(self.content)
        self.content_layout.setAlignment(Qt.AlignmentFlag.AlignTop)
        self.content_layout.setContentsMargins(20, 20, 20, 20)
        self.password_labels = {}

        main_layout.addWidget(sidebar)
        main_layout.addWidget(self.content, stretch=1)

        # Auto-Logout Timer
        self.inactivity_timer = QTimer(self)
        self.inactivity_timer.timeout.connect(self.logout)
        self.inactivity_timer.setInterval(300000)  # 5 minutes

        self.apply_theme()
        self.showFullScreen()
        self.installEventFilter(self)
        self.show_login()

    def apply_theme(self):
        if self.is_dark_mode:
            self.setStyleSheet("background: qlineargradient(x1:0, y1:0, x2:1, y2:1, stop:0 #2D2D2D, stop:1 #1A1A1A);")
            self.content.setStyleSheet("background: rgba(50, 50, 50, 0.95); border-radius: 12px;")
        else:
            self.setStyleSheet("background: qlineargradient(x1:0, y1:0, x2:1, y2:1, stop:0 #E0E7FF, stop:1 #FFFFFF);")
            self.content.setStyleSheet("background: rgba(255, 255, 255, 0.95); border-radius: 12px;")

    def eventFilter(self, obj, event):
        if event.type() in (QEvent.Type.MouseMove, QEvent.Type.KeyPress, QEvent.Type.MouseButtonPress):
            self.reset_inactivity_timer()
        if event.type() == QEvent.Type.KeyPress and event.key() == Qt.Key.Key_Escape:
            if self.isFullScreen():
                self.showNormal()
            else:
                self.showFullScreen()
            return True
        return super().eventFilter(obj, event)

    def reset_inactivity_timer(self):
        if hasattr(self, 'user_id') and self.user_id:
            self.inactivity_timer.start()

    def clear_content(self):
        for widget in self.content.findChildren(QWidget):
            widget.deleteLater()

    def check_login_before_action(self, action):
        if not hasattr(self, 'user_id') or self.user_id is None:
            self.show_not_logged_in_message()
        else:
            action()

    def show_not_logged_in_message(self):
        self.clear_content()
        message = QLabel("Please log in to access this feature.")
        message.setFont(QFont("Open Sans", 14))
        message.setStyleSheet("color: #FF6B6B; padding: 20px;")
        self.content_layout.addWidget(message, alignment=Qt.AlignmentFlag.AlignCenter)

    def show_login(self):
        self.clear_content()
        title = QLabel("Welcome Back")
        title.setFont(QFont("Montserrat", 30, QFont.Weight.Bold))
        title.setStyleSheet(f"color: {'#4A90E2' if not self.is_dark_mode else '#38b6ff'};")
        self.content_layout.addWidget(title, alignment=Qt.AlignmentFlag.AlignCenter)

        self.entries = {}
        for label, key, echo, placeholder in [
            ("Username", "username", QLineEdit.EchoMode.Normal, "Enter your username"),
            ("Master Password", "password", QLineEdit.EchoMode.Password, "Enter your master password")
        ]:
            lbl = QLabel(label)
            lbl.setFont(QFont("Open Sans", 12))
            lbl.setStyleSheet(f"color: {'#333' if not self.is_dark_mode else '#E0E7FF'};")
            self.content_layout.addWidget(lbl)
            entry = QLineEdit()
            entry.setFont(QFont("Open Sans", 14))
            entry.setStyleSheet(f"""
                background: {'#F5F6F5' if not self.is_dark_mode else '#3A3A3A'}; 
                border: none; 
                padding: 8px; 
                border-radius: 5px; 
                color: {'#333' if not self.is_dark_mode else '#E0E7FF'};
            """)
            entry.setPlaceholderText(placeholder)
            entry.setEchoMode(echo)
            palette = entry.palette()
            palette.setColor(QPalette.ColorRole.PlaceholderText, QColor("#888"))
            entry.setPalette(palette)
            self.content_layout.addWidget(entry)
            self.entries[key] = entry

        login_btn = QPushButton("Login")
        login_btn.setFont(QFont("Montserrat", 16, QFont.Weight.Bold))
        login_btn.setStyleSheet("""
            background: #4A90E2; 
            color: white; 
            padding: 12px 30px; 
            border-radius: 8px;
            border: none;
        """)
        login_btn.clicked.connect(self.login)
        self.content_layout.addWidget(login_btn, alignment=Qt.AlignmentFlag.AlignCenter)

        forgot_btn = QPushButton("Forgot Password?")
        forgot_btn.setFont(QFont("Montserrat", 12))
        forgot_btn.setStyleSheet("""
            background: #FFD166; 
            color: black; 
            padding: 8px 20px; 
            border-radius: 5px;
        """)
        forgot_btn.clicked.connect(self.show_recovery_options)
        self.content_layout.addWidget(forgot_btn, alignment=Qt.AlignmentFlag.AlignCenter)

    def show_recovery_options(self):
        self.clear_content()
        title = QLabel("Recover Your Account")
        title.setFont(QFont("Montserrat", 30, QFont.Weight.Bold))
        title.setStyleSheet(f"color: {'#4A90E2' if not self.is_dark_mode else '#38b6ff'};")
        self.content_layout.addWidget(title, alignment=Qt.AlignmentFlag.AlignCenter)

        user_id = self.entries["username"].text()
        if not user_id:
            error = QLabel("Please enter your username first.")
            error.setFont(QFont("Open Sans", 12))
            error.setStyleSheet("color: #FF6B6B;")
            self.content_layout.addWidget(error, alignment=Qt.AlignmentFlag.AlignCenter)
            return

        options = [
            ("Face Scan", lambda: self.recover_with_face(user_id), "Use your webcam to scan your face"),
            ("Device Fingerprint", lambda: self.recover_with_device(user_id), "Verify using this device"),
            ("Trusted Contact", lambda: self.recover_with_contact(user_id), "Enter key from trusted contact")
        ]
        for text, cmd, desc in options:
            btn_frame = QFrame()
            btn_layout = QVBoxLayout(btn_frame)
            btn = QPushButton(text)
            btn.setFont(QFont("Montserrat", 14, QFont.Weight.Bold))
            btn.setStyleSheet("""
                background: #10B981; 
                color: white; 
                padding: 10px; 
                border-radius: 5px;
            """)
            btn.clicked.connect(cmd)
            btn_layout.addWidget(btn)
            desc_label = QLabel(desc)
            desc_label.setFont(QFont("Open Sans", 10))
            desc_label.setStyleSheet(f"color: {'#333' if not self.is_dark_mode else '#E0E7FF'};")
            desc_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
            btn_layout.addWidget(desc_label)
            self.content_layout.addWidget(btn_frame, alignment=Qt.AlignmentFlag.AlignCenter)

    def recover_with_face(self, user_id):
        doc = users_ref.document(user_id).get()
        if not doc.exists or "face_recovery_key" not in doc.to_dict():
            self.show_error("Face scan not set up for this user.")
            return

        face_encoding = self.capture_face()
        if face_encoding is None:
            self.show_error("Failed to capture face. Ensure webcam is connected and face is visible.")
            return

        stored_encoding = base64.b64decode(doc.to_dict()["face_encoding"])
        if face_recognition.compare_faces([stored_encoding], face_encoding)[0]:
            private_key = decrypt_with_key(doc.to_dict()["face_recovery_key"], base64.b64encode(face_encoding).decode())
            self.reset_master_password(user_id, private_key)
        else:
            self.show_error("Face does not match.")

    def recover_with_device(self, user_id):
        doc = users_ref.document(user_id).get()
        if not doc.exists or "device_recovery_key" not in doc.to_dict():
            self.show_error("Device fingerprint not set up for this user.")
            return

        device_id = self.get_device_id()
        private_key = decrypt_with_key(doc.to_dict()["device_recovery_key"], device_id)
        if private_key:
            self.reset_master_password(user_id, private_key)
        else:
            self.show_error("This device does not match the original.")

    def recover_with_contact(self, user_id):
        doc = users_ref.document(user_id).get()
        if not doc.exists or "contact_recovery_key" not in doc.to_dict():
            self.show_error("Trusted contact not set up for this user.")
            return

        self.clear_content()
        title = QLabel("Trusted Contact Recovery")
        title.setFont(QFont("Montserrat", 30, QFont.Weight.Bold))
        title.setStyleSheet(f"color: {'#4A90E2' if not self.is_dark_mode else '#38b6ff'};")
        self.content_layout.addWidget(title, alignment=Qt.AlignmentFlag.AlignCenter)

        lbl = QLabel("Enter recovery key from your trusted contact:")
        lbl.setFont(QFont("Open Sans", 12))
        lbl.setStyleSheet(f"color: {'#333' if not self.is_dark_mode else '#E0E7FF'};")
        self.content_layout.addWidget(lbl)
        key_entry = QLineEdit()
        key_entry.setFont(QFont("Open Sans", 14))
        key_entry.setStyleSheet(f"""
            background: {'#F5F6F5' if not self.is_dark_mode else '#3A3A3A'}; 
            border: none; 
            padding: 8px; 
            border-radius: 5px; 
            color: {'#333' if not self.is_dark_mode else '#E0E7FF'};
        """)
        key_entry.setPlaceholderText("e.g., paste key provided by your contact")
        palette = key_entry.palette()
        palette.setColor(QPalette.ColorRole.PlaceholderText, QColor("#888"))
        key_entry.setPalette(palette)
        self.content_layout.addWidget(key_entry)

        submit_btn = QPushButton("Submit")
        submit_btn.setFont(QFont("Montserrat", 12))
        submit_btn.setStyleSheet("""
            background: #4A90E2; 
            color: white; 
            padding: 8px 20px; 
            border-radius: 5px;
        """)
        submit_btn.clicked.connect(lambda: self.verify_contact_key(user_id, key_entry.text()))
        self.content_layout.addWidget(submit_btn, alignment=Qt.AlignmentFlag.AlignCenter)

    def verify_contact_key(self, user_id, contact_key):
        doc = users_ref.document(user_id).get()
        private_key = decrypt_with_key(doc.to_dict()["contact_recovery_key"], contact_key)
        if private_key:
            self.reset_master_password(user_id, private_key)
        else:
            self.show_error("Invalid recovery key.")

    def reset_master_password(self, user_id, private_key):
        self.clear_content()
        title = QLabel("Reset Master Password")
        title.setFont(QFont("Montserrat", 30, QFont.Weight.Bold))
        title.setStyleSheet(f"color: {'#4A90E2' if not self.is_dark_mode else '#38b6ff'};")
        self.content_layout.addWidget(title, alignment=Qt.AlignmentFlag.AlignCenter)

        new_pass = QLineEdit()
        new_pass.setEchoMode(QLineEdit.EchoMode.Password)
        new_pass.setStyleSheet(f"""
            background: {'#F5F6F5' if not self.is_dark_mode else '#3A3A3A'}; 
            border: none; 
            padding: 8px; 
            border-radius: 5px; 
            color: {'#333' if not self.is_dark_mode else '#E0E7FF'};
        """)
        new_pass.setPlaceholderText("Enter new master password")
        palette = new_pass.palette()
        palette.setColor(QPalette.ColorRole.PlaceholderText, QColor("#888"))
        new_pass.setPalette(palette)
        self.content_layout.addWidget(QLabel("New Master Password:"))
        self.content_layout.addWidget(new_pass)

        confirm_pass = QLineEdit()
        confirm_pass.setEchoMode(QLineEdit.EchoMode.Password)
        confirm_pass.setStyleSheet(f"""
            background: {'#F5F6F5' if not self.is_dark_mode else '#3A3A3A'}; 
            border: none; 
            padding: 8px; 
            border-radius: 5px; 
            color: {'#333' if not self.is_dark_mode else '#E0E7FF'};
        """)
        confirm_pass.setPlaceholderText("Confirm new master password")
        palette = confirm_pass.palette()
        palette.setColor(QPalette.ColorRole.PlaceholderText, QColor("#888"))
        confirm_pass.setPalette(palette)
        self.content_layout.addWidget(QLabel("Confirm Password:"))
        self.content_layout.addWidget(confirm_pass)

        save_btn = QPushButton("Save")
        save_btn.setFont(QFont("Montserrat", 16, QFont.Weight.Bold))
        save_btn.setStyleSheet("""
            background: #4A90E2; 
            color: white; 
            padding: 10px; 
            border-radius: 8px;
        """)
        save_btn.clicked.connect(lambda: self.save_new_password(user_id, private_key, new_pass.text(), confirm_pass.text()))
        self.content_layout.addWidget(save_btn, alignment=Qt.AlignmentFlag.AlignCenter)

    def save_new_password(self, user_id, private_key, new_pass, confirm_pass):
        if new_pass != confirm_pass:
            self.show_error("Passwords do not match.")
            return
        encrypted_private_key = encrypt_with_key(private_key, new_pass)
        users_ref.document(user_id).update({"encrypted_private_key": encrypted_private_key})
        self.master_password = new_pass
        self.private_key = private_key
        self.user_id = user_id
        self.public_key = users_ref.document(user_id).get().to_dict()["public_key"]
        for btn in self.sidebar_buttons.values():
            btn.setEnabled(True)
        self.reset_inactivity_timer()
        self.show_view_credentials()

    def show_error(self, message):
        self.clear_content()
        error = QLabel(message)
        error.setFont(QFont("Open Sans", 14))
        error.setStyleSheet("color: #FF6B6B;")
        self.content_layout.addWidget(error, alignment=Qt.AlignmentFlag.AlignCenter)
        back_btn = QPushButton("Back to Login")
        back_btn.setFont(QFont("Montserrat", 12))
        back_btn.setStyleSheet("""
            background: #4A90E2; 
            color: white; 
            padding: 8px 20px; 
            border-radius: 5px;
        """)
        back_btn.clicked.connect(self.show_login)
        self.content_layout.addWidget(back_btn, alignment=Qt.AlignmentFlag.AlignCenter)

    def capture_face(self):
        cap = cv2.VideoCapture(0)
        if not cap.isOpened():
            print("Error: Could not open webcam.")
            return None
        ret, frame = cap.read()
        if not ret:
            print("Error: Could not read frame.")
            cap.release()
            return None
        rgb_frame = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
        encodings = face_recognition.face_encodings(rgb_frame)
        cap.release()
        return encodings[0] if encodings else None

    def get_device_id(self):
        return str(uuid.getnode()) + str(psutil.disk_partitions()[0].device if psutil.disk_partitions() else "default")

    def prompt_setup_recovery(self):
        self.clear_content()
        title = QLabel("Set Up Recovery Options")
        title.setFont(QFont("Montserrat", 30, QFont.Weight.Bold))
        title.setStyleSheet(f"color: {'#4A90E2' if not self.is_dark_mode else '#38b6ff'};")
        self.content_layout.addWidget(title, alignment=Qt.AlignmentFlag.AlignCenter)

        face_label = QLabel("Face Scan will be captured automatically.")
        face_label.setFont(QFont("Open Sans", 12))
        face_label.setStyleSheet(f"color: {'#333' if not self.is_dark_mode else '#E0E7FF'};")
        self.content_layout.addWidget(face_label, alignment=Qt.AlignmentFlag.AlignCenter)

        device_label = QLabel("Device fingerprint will be set for this device.")
        device_label.setFont(QFont("Open Sans", 12))
        device_label.setStyleSheet(f"color: {'#333' if not self.is_dark_mode else '#E0E7FF'};")
        self.content_layout.addWidget(device_label, alignment=Qt.AlignmentFlag.AlignCenter)

        contact_label = QLabel("Trusted Contact Username (optional):")
        contact_label.setFont(QFont("Open Sans", 12))
        contact_label.setStyleSheet(f"color: {'#333' if not self.is_dark_mode else '#E0E7FF'};")
        self.content_layout.addWidget(contact_label)
        contact_entry = QLineEdit()
        contact_entry.setFont(QFont("Open Sans", 14))
        contact_entry.setStyleSheet(f"""
            background: {'#F5F6F5' if not self.is_dark_mode else '#3A3A3A'}; 
            border: none; 
            padding: 8px; 
            border-radius: 5px; 
            color: {'#333' if not self.is_dark_mode else '#E0E7FF'};
        """)
        contact_entry.setPlaceholderText("e.g., friend123")
        palette = contact_entry.palette()
        palette.setColor(QPalette.ColorRole.PlaceholderText, QColor("#888"))
        contact_entry.setPalette(palette)
        self.content_layout.addWidget(contact_entry)

        submit_btn = QPushButton("Complete Setup")
        submit_btn.setFont(QFont("Montserrat", 16, QFont.Weight.Bold))
        submit_btn.setStyleSheet("""
            background: #4A90E2; 
            color: white; 
            padding: 10px; 
            border-radius: 8px;
        """)
        submit_btn.clicked.connect(lambda: self.finish_setup(contact_entry.text()))
        self.content_layout.addWidget(submit_btn, alignment=Qt.AlignmentFlag.AlignCenter)

    def finish_setup(self, trusted_contact_id):
        face_encoding = self.capture_face()
        if face_encoding is None:
            self.show_error("Failed to capture face. Try again.")
            return
        device_id = self.get_device_id()
        self.public_key, self.private_key = generate_and_store_keys(
            self.user_id, self.master_password, face_encoding, device_id, trusted_contact_id or None
        )
        for btn in self.sidebar_buttons.values():
            btn.setEnabled(True)
        self.reset_inactivity_timer()
        self.show_welcome_guide()

    def login(self):
        try:
            user_id = self.entries["username"].text()
            master_password = self.entries["password"].text()
            doc = users_ref.document(user_id).get()
            print(f"Logging in user: {user_id}")
            if doc.exists:
                encrypted_private_key = doc.to_dict()["encrypted_private_key"]
                self.public_key = doc.to_dict()["public_key"]
                self.private_key = decrypt_with_key(encrypted_private_key, master_password)
                if self.private_key is None:
                    raise ValueError("Failed to decrypt private key - wrong master password?")
                self.user_id = user_id
                self.master_password = master_password
                print(f"Login successful for {user_id}")
                for btn in self.sidebar_buttons.values():
                    btn.setEnabled(True)
                self.reset_inactivity_timer()
                self.show_view_credentials()
            else:
                self.user_id = user_id
                self.master_password = master_password
                self.prompt_setup_recovery()
        except Exception as e:
            error_label = QLabel(f"Login failed: {str(e)}")
            error_label.setFont(QFont("Open Sans", 12))
            error_label.setStyleSheet("color: red;")
            self.content_layout.addWidget(error_label, alignment=Qt.AlignmentFlag.AlignCenter)

    def logout(self):
        self.inactivity_timer.stop()
        self.user_id = None
        self.master_password = None
        self.public_key = None
        self.private_key = None
        self.password_labels.clear()
        for btn in self.sidebar_buttons.values():
            btn.setEnabled(False)
        print("Logged out")
        self.show_login()

    def show_settings(self):
        self.clear_content()
        self.content_layout.setSpacing(20)
        settings_container = QWidget()
        settings_container.setFixedWidth(600)
        settings_container.setFixedHeight(500)
        settings_layout = QVBoxLayout(settings_container)
        settings_layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
        settings_layout.setSpacing(20)

        title = QLabel("Settings")
        title.setFont(QFont("Montserrat", 48, QFont.Weight.Bold))
        title.setStyleSheet(f"color: {'#4A90E2' if not self.is_dark_mode else '#38b6ff'};")
        settings_layout.addWidget(title, alignment=Qt.AlignmentFlag.AlignCenter)

        account_frame = QFrame()
        account_frame.setStyleSheet(f"""
            background: {'#F9FAFB' if not self.is_dark_mode else '#313131'};
            border-radius: 10px;
            box-shadow: 0 2px 6px rgba(0,0,0,0.1);
        """)
        account_layout = QHBoxLayout(account_frame)
        account_icon = QLabel("👤")
        account_icon.setFont(QFont("Open Sans", 50))
        account_icon.setStyleSheet(f"color: {'#4A90E2' if not self.is_dark_mode else '#38b6ff'};")
        account_layout.addWidget(account_icon)
        account_label = QLabel(f"{self.user_id}")
        account_label.setFont(QFont("Open Sans", 38, QFont.Weight.Medium))
        account_label.setStyleSheet(f"color: {'#333' if not self.is_dark_mode else '#E0E7FF'};")
        account_layout.addWidget(account_label)
        settings_layout.addWidget(account_frame)

        theme_btn = QPushButton("Switch to Dark Mode" if not self.is_dark_mode else "Switch to Light Mode")
        theme_btn.setFont(QFont("Montserrat", 14, QFont.Weight.Bold))
        theme_btn.setStyleSheet("""
            QPushButton {
                background: #4A90E2;
                color: white;
                padding: 12px 25px;
                border-radius: 8px;
                border: none;
                box-shadow: 0 2px 4px rgba(0,0,0,0.15);
            }
            QPushButton:hover {
                background: #357ABD;
            }
        """)
        theme_btn.clicked.connect(self.toggle_theme)
        settings_layout.addWidget(theme_btn, alignment=Qt.AlignmentFlag.AlignCenter)

        logout_btn = QPushButton("Logout")
        logout_btn.setFont(QFont("Montserrat", 14, QFont.Weight.Bold))
        logout_btn.setStyleSheet("""
            QPushButton {
                background: #FF6B6B;
                color: white;
                padding: 12px 25px;
                border-radius: 8px;
                border: none;
                box-shadow: 0 2px 4px rgba(0,0,0,0.15);
            }
            QPushButton:hover {
                background: #E55A5A;
            }
        """)
        logout_btn.clicked.connect(self.logout)
        settings_layout.addWidget(logout_btn, alignment=Qt.AlignmentFlag.AlignCenter)

        contact_btn = QPushButton("Contact Developer")
        contact_btn.setFont(QFont("Montserrat", 14, QFont.Weight.Bold))
        contact_btn.setStyleSheet("""
            QPushButton {
                background: #10B981;
                color: white;
                padding: 12px 25px;
                border-radius: 8px;
                border: none;
                box-shadow: 0 2px 4px rgba(0,0,0,0.15);
            }
            QPushButton:hover {
                background: #059669;
            }
        """)
        contact_btn.clicked.connect(lambda: QDesktopServices.openUrl(QUrl("https://www.linkedin.com/in/-apoorv-/")))
        settings_layout.addWidget(contact_btn, alignment=Qt.AlignmentFlag.AlignCenter)

        about_btn = QPushButton("About PassGuard")
        about_btn.setFont(QFont("Montserrat", 14, QFont.Weight.Bold))
        about_btn.setStyleSheet("""
            QPushButton {
                background: #6B7280;
                color: white;
                padding: 12px 25px;
                border-radius: 8px;
                border: none;
                box-shadow: 0 2px 4px rgba(0,0,0,0.15);
            }
            QPushButton:hover {
                background: #4B5563;
            }
        """)
        about_btn.clicked.connect(self.show_about)
        settings_layout.addWidget(about_btn, alignment=Qt.AlignmentFlag.AlignCenter)

        self.content_layout.addWidget(settings_container, alignment=Qt.AlignmentFlag.AlignCenter)

    def toggle_theme(self):
        self.is_dark_mode = not self.is_dark_mode
        self.apply_theme()
        self.show_settings()

    def show_about(self):
        self.clear_content()
        title = QLabel("About PassGuard")
        title.setFont(QFont("Montserrat", 30, QFont.Weight.Bold))
        title.setStyleSheet(f"color: {'#4A90E2' if not self.is_dark_mode else '#38b6ff'};")
        self.content_layout.addWidget(title, alignment=Qt.AlignmentFlag.AlignCenter)

        about_text = QLabel(
            "PassGuard v1.0\n\n"
            "A secure password manager built to keep your credentials safe.\n"
            "Developed by Apoorv Gupta\n"
            "© 2025 All rights reserved."
        )
        about_text.setFont(QFont("Open Sans", 12))
        about_text.setStyleSheet(f"color: {'#333' if not self.is_dark_mode else '#E0E7FF'}; padding: 10px;")
        about_text.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.content_layout.addWidget(about_text)

        back_btn = QPushButton("Back to Settings")
        back_btn.setFont(QFont("Montserrat", 12))
        back_btn.setStyleSheet("""
            background: #4A90E2; 
            color: white; 
            padding: 8px 20px; 
            border-radius: 5px;
        """)
        back_btn.clicked.connect(self.show_settings)
        self.content_layout.addWidget(back_btn, alignment=Qt.AlignmentFlag.AlignCenter)

    def show_welcome_guide(self):
        self.clear_content()
        title = QLabel("Welcome to PassGuard!")
        title.setFont(QFont("Montserrat", 30, QFont.Weight.Bold))
        title.setStyleSheet(f"color: {'#4A90E2' if not self.is_dark_mode else '#38b6ff'};")
        self.content_layout.addWidget(title, alignment=Qt.AlignmentFlag.AlignCenter)

        guide_text = QLabel(
            "Here’s how to get started:\n\n"
            "1. Click 'Add Credential' to save a new password.\n"
            "2. Fill in the website, username, password, and category—then hit 'Save'.\n"
            "3. Use 'View Credentials' to see your saved entries—search or filter by category.\n"
            "4. Click 'Show' to reveal, 'Copy' to paste, or 'Edit' to update.\n\n"
            "Your data is encrypted—keep your master password safe!"
        )
        guide_text.setFont(QFont("Open Sans", 12))
        guide_text.setStyleSheet(f"color: {'#333' if not self.is_dark_mode else '#E0E7FF'}; padding: 10px;")
        guide_text.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.content_layout.addWidget(guide_text)

        start_btn = QPushButton("Got it, let’s start!")
        start_btn.setFont(QFont("Montserrat", 16, QFont.Weight.Bold))
        start_btn.setStyleSheet("""
            background: #4A90E2; 
            color: white; 
            padding: 10px; 
            border-radius: 8px;
        """)
        start_btn.clicked.connect(self.show_add_credential)
        self.content_layout.addWidget(start_btn, alignment=Qt.AlignmentFlag.AlignCenter)

    def show_add_credential(self):
        self.clear_content()
        title = QLabel("Add Credential")
        title.setFont(QFont("Montserrat", 30, QFont.Weight.Bold))
        title.setStyleSheet(f"color: {'#4A90E2' if not self.is_dark_mode else '#38b6ff'};")
        self.content_layout.addWidget(title, alignment=Qt.AlignmentFlag.AlignCenter)

        entries = {}
        for label, key, placeholder in [
            ("Website", "website", "e.g., example.com"),
            ("Username", "username", "e.g., yourname"),
            ("Password", "password", "Enter your password"),
            ("Category", "category", "e.g., Work, Personal")
        ]:
            lbl = QLabel(label)
            lbl.setFont(QFont("Open Sans", 12))
            lbl.setStyleSheet(f"color: {'#333' if not self.is_dark_mode else '#E0E7FF'};")
            self.content_layout.addWidget(lbl)
            entry = QLineEdit()
            entry.setFont(QFont("Open Sans", 14))
            entry.setStyleSheet(f"""
                background: {'#F5F6F5' if not self.is_dark_mode else '#3A3A3A'}; 
                border: none; 
                padding: 8px; 
                border-radius: 5px; 
                color: {'#333' if not self.is_dark_mode else '#E0E7FF'};
            """)
            entry.setPlaceholderText(placeholder)
            if key == "password":
                entry.setEchoMode(QLineEdit.EchoMode.Password)
            palette = entry.palette()
            palette.setColor(QPalette.ColorRole.PlaceholderText, QColor("#888"))
            entry.setPalette(palette)
            self.content_layout.addWidget(entry)
            entries[key] = entry

        strength_label = QLabel("Password Strength: N/A")
        strength_label.setFont(QFont("Open Sans", 12))
        strength_label.setStyleSheet(f"color: {'#333' if not self.is_dark_mode else '#E0E7FF'};")
        self.content_layout.addWidget(strength_label, alignment=Qt.AlignmentFlag.AlignCenter)

        def update_strength():
            password = entries["password"].text()
            if password:
                strength, color = check_password_strength(password)
                strength_label.setText(f"Password Strength: {strength}")
                strength_label.setStyleSheet(f"color: {color};")
            else:
                strength_label.setText("Password Strength: N/A")
                strength_label.setStyleSheet(f"color: {'#333' if not self.is_dark_mode else '#E0E7FF'};")

        entries["password"].textChanged.connect(update_strength)

        generate_btn = QPushButton("Generate Password")
        generate_btn.setFont(QFont("Montserrat", 12))
        generate_btn.setStyleSheet("""
            background: #10B981; 
            color: white; 
            padding: 8px 20px; 
            border-radius: 5px;
        """)
        generate_btn.clicked.connect(lambda: [entries["password"].setText(generate_password()), update_strength()])
        self.content_layout.addWidget(generate_btn, alignment=Qt.AlignmentFlag.AlignCenter)

        save_btn = QPushButton("Save")
        save_btn.setFont(QFont("Montserrat", 16, QFont.Weight.Bold))
        save_btn.setStyleSheet("""
            background: #4A90E2; 
            color: white; 
            padding: 10px; 
            border-radius: 8px;
        """)
        save_btn.clicked.connect(lambda: self.store_credential(entries))
        self.content_layout.addWidget(save_btn, alignment=Qt.AlignmentFlag.AlignCenter)

    def show_view_credentials(self):
        self.clear_content()
        title = QLabel("View Credentials")
        title.setFont(QFont("Montserrat", 30, QFont.Weight.Bold))
        title.setStyleSheet(f"color: {'#4A90E2' if not self.is_dark_mode else '#38b6ff'};")
        self.content_layout.addWidget(title, alignment=Qt.AlignmentFlag.AlignCenter)

        search_bar = QLineEdit()
        search_bar.setFont(QFont("Open Sans", 14))
        search_bar.setStyleSheet(f"""
            background: {'#F5F6F5' if not self.is_dark_mode else '#3A3A3A'}; 
            border: none; 
            padding: 8px; 
            border-radius: 5px; 
            color: {'#333' if not self.is_dark_mode else '#E0E7FF'};
        """)
        search_bar.setPlaceholderText("Search by website or username...")
        palette = search_bar.palette()
        palette.setColor(QPalette.ColorRole.PlaceholderText, QColor("#888"))
        search_bar.setPalette(palette)
        self.content_layout.addWidget(search_bar)

        category_filter = QComboBox()
        category_filter.setFont(QFont("Open Sans", 12))
        category_filter.setStyleSheet(f"""
            background: {'#F5F6F5' if not self.is_dark_mode else '#3A3A3A'}; 
            border: none; 
            padding: 8px; 
            border-radius: 5px; 
            color: {'#333' if not self.is_dark_mode else '#E0E7FF'};
        """)
        category_filter.addItem("All Categories")
        categories = set()
        docs = credentials_ref.where("user_id", "==", self.user_id).stream()
        for doc in docs:
            data = doc.to_dict()
            category = data.get("category", "")
            if category:
                categories.add(category)
        for category in sorted(categories):
            category_filter.addItem(category)
        self.content_layout.addWidget(category_filter)

        credential_list = QListWidget()
        credential_list.setFont(QFont("Open Sans", 12))
        credential_list.setStyleSheet(f"""
            background: {'#E0E7FF' if not self.is_dark_mode else '#3A3A3A'}; 
            border: none; 
            padding: 10px; 
            border-radius: 5px;
        """)
        credential_list.setSpacing(5)
        credential_list.setMinimumWidth(600)

        def update_credential_list():
            credential_list.clear()
            search_text = search_bar.text().lower()
            selected_category = category_filter.currentText()
            docs = credentials_ref.where("user_id", "==", self.user_id).stream()
            for doc in docs:
                data = doc.to_dict()
                data["doc_id"] = doc.id
                website = data["website"].lower()
                username = data["username"].lower()
                category = data.get("category", "")
                if (search_text in website or search_text in username) and \
                   (selected_category == "All Categories" or category == selected_category):
                    item = QListWidgetItem()
                    widget = QWidget()
                    layout = QHBoxLayout(widget)
                    layout.setContentsMargins(5, 5, 5, 5)

                    label_text = f"Website: {data['website']} | Username: {data['username']}"
                    if category:
                        label_text += f" | Category: {category}"
                    label = QLabel(label_text)
                    label.setFont(QFont("Open Sans", 12))
                    label.setStyleSheet(f"color: {'#333' if not self.is_dark_mode else '#E0E7FF'};")
                    layout.addWidget(label)

                    password_label = QLabel("••••••••")
                    password_label.setFont(QFont("Open Sans", 12))
                    password_label.setStyleSheet(f"color: {'#4A90E2' if not self.is_dark_mode else '#38b6ff'};")
                    self.password_labels[data["doc_id"]] = password_label
                    layout.addWidget(password_label)

                    show_btn = QPushButton("Show")
                    show_btn.setFont(QFont("Montserrat", 10))
                    show_btn.setStyleSheet("""
                        background: #4A90E2; 
                        color: white; 
                        padding: 5px; 
                        border-radius: 5px;
                    """)
                    show_btn.clicked.connect(lambda checked, d=data, btn=show_btn: self.toggle_password(d, btn))
                    layout.addWidget(show_btn)

                    copy_btn = QPushButton("Copy")
                    copy_btn.setFont(QFont("Montserrat", 10))
                    copy_btn.setStyleSheet("""
                        background: #10B981; 
                        color: white; 
                        padding: 5px; 
                        border-radius: 5px;
                    """)
                    copy_btn.clicked.connect(lambda checked, d=data: self.copy_password(d))
                    layout.addWidget(copy_btn)

                    edit_btn = QPushButton("Edit")
                    edit_btn.setFont(QFont("Montserrat", 10))
                    edit_btn.setStyleSheet("""
                        background: #FFD166; 
                        color: black; 
                        padding: 5px; 
                        border-radius: 5px;
                    """)
                    edit_btn.clicked.connect(lambda checked, d=data: self.show_edit_credential(d))
                    layout.addWidget(edit_btn)

                    delete_btn = QPushButton("Delete")
                    delete_btn.setFont(QFont("Montserrat", 10))
                    delete_btn.setStyleSheet("""
                        background: #FF6B6B; 
                        color: white; 
                        padding: 5px; 
                        border-radius: 5px;
                    """)
                    delete_btn.clicked.connect(lambda checked, d=data: self.delete_credential(d["doc_id"]))
                    layout.addWidget(delete_btn)

                    item.setSizeHint(widget.sizeHint().grownBy(QMargins(0, 10, 0, 10)))
                    credential_list.addItem(item)
                    credential_list.setItemWidget(item, widget)

        search_bar.textChanged.connect(update_credential_list)
        category_filter.currentTextChanged.connect(update_credential_list)
        update_credential_list()
        self.content_layout.addWidget(credential_list, stretch=1)

    def toggle_password(self, data, button):
        password_label = self.password_labels.get(data["doc_id"])
        if button.text() == "Show":
            password = decrypt_password(data, self.master_password, self.private_key)
            password_label.setText(password)
            button.setText("Hide")
        else:
            password_label.setText("••••••••")
            button.setText("Show")

    def copy_password(self, data):
        password = decrypt_password(data, self.master_password, self.private_key)
        clipboard = QApplication.clipboard()
        clipboard.setText(password)

    def delete_credential(self, doc_id):
        credentials_ref.document(doc_id).delete()
        self.show_view_credentials()

    def show_edit_credential(self, data):
        self.clear_content()
        title = QLabel("Edit Credential")
        title.setFont(QFont("Montserrat", 30, QFont.Weight.Bold))
        title.setStyleSheet(f"color: {'#4A90E2' if not self.is_dark_mode else '#38b6ff'};")
        self.content_layout.addWidget(title, alignment=Qt.AlignmentFlag.AlignCenter)

        entries = {}
        for label, key, value, placeholder in [
            ("Website", "website", data["website"], "e.g., example.com"),
            ("Username", "username", data["username"], "e.g., yourname"),
            ("Password", "password", decrypt_password(data, self.master_password, self.private_key), "Enter your password"),
            ("Category", "category", data.get("category", ""), "e.g., Work, Personal")
        ]:
            lbl = QLabel(label)
            lbl.setFont(QFont("Open Sans", 12))
            lbl.setStyleSheet(f"color: {'#333' if not self.is_dark_mode else '#E0E7FF'};")
            self.content_layout.addWidget(lbl)
            entry = QLineEdit()
            entry.setFont(QFont("Open Sans", 14))
            entry.setStyleSheet(f"""
                background: {'#F5F6F5' if not self.is_dark_mode else '#3A3A3A'}; 
                border: none; 
                padding: 8px; 
                border-radius: 5px; 
                color: {'#333' if not self.is_dark_mode else '#E0E7FF'};
            """)
            entry.setText(value)
            entry.setPlaceholderText(placeholder)
            if key == "password":
                entry.setEchoMode(QLineEdit.EchoMode.Password)
            palette = entry.palette()
            palette.setColor(QPalette.ColorRole.PlaceholderText, QColor("#888"))
            entry.setPalette(palette)
            self.content_layout.addWidget(entry)
            entries[key] = entry

        strength_label = QLabel("Password Strength: N/A")
        strength_label.setFont(QFont("Open Sans", 12))
        strength_label.setStyleSheet(f"color: {'#333' if not self.is_dark_mode else '#E0E7FF'};")
        self.content_layout.addWidget(strength_label, alignment=Qt.AlignmentFlag.AlignCenter)

        def update_strength():
            password = entries["password"].text()
            if password:
                strength, color = check_password_strength(password)
                strength_label.setText(f"Password Strength: {strength}")
                strength_label.setStyleSheet(f"color: {color};")
            else:
                strength_label.setText("Password Strength: N/A")
                strength_label.setStyleSheet(f"color: {'#333' if not self.is_dark_mode else '#E0E7FF'};")

        entries["password"].textChanged.connect(update_strength)
        update_strength()

        generate_btn = QPushButton("Generate Password")
        generate_btn.setFont(QFont("Montserrat", 12))
        generate_btn.setStyleSheet("""
            background: #10B981; 
            color: white; 
            padding: 8px 20px; 
            border-radius: 5px;
        """)
        generate_btn.clicked.connect(lambda: [entries["password"].setText(generate_password()), update_strength()])
        self.content_layout.addWidget(generate_btn, alignment=Qt.AlignmentFlag.AlignCenter)

        save_btn = QPushButton("Save Changes")
        save_btn.setFont(QFont("Montserrat", 16, QFont.Weight.Bold))
        save_btn.setStyleSheet("""
            background: #4A90E2; 
            color: white; 
            padding: 10px; 
            border-radius: 8px;
        """)
        save_btn.clicked.connect(lambda: self.update_credential(data["doc_id"], entries))
        self.content_layout.addWidget(save_btn, alignment=Qt.AlignmentFlag.AlignCenter)

    def store_credential(self, entries):
        encrypted_data = encrypt_password(entries["password"].text(), self.master_password, self.public_key)
        credentials_ref.add({
            "user_id": self.user_id,
            "website": entries["website"].text(),
            "username": entries["username"].text(),
            "category": entries["category"].text(),
            **encrypted_data
        })
        self.show_view_credentials()

    def update_credential(self, doc_id, entries):
        encrypted_data = encrypt_password(entries["password"].text(), self.master_password, self.public_key)
        credentials_ref.document(doc_id).update({
            "website": entries["website"].text(),
            "username": entries["username"].text(),
            "category": entries["category"].text(),
            **encrypted_data
        })
        self.show_view_credentials()

if __name__ == "__main__":
    app = QApplication(sys.argv)
    app.setStyle("Fusion")
    palette = QPalette()
    palette.setColor(QPalette.ColorRole.Window, QColor("#F5F6F5"))
    app.setPalette(palette)
    window = PasswordManagerWindow()
    sys.exit(app.exec())