import sys
from PyQt6.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
                             QPushButton, QLineEdit, QLabel, QFrame, QListWidget, QListWidgetItem, QComboBox)
from PyQt6.QtCore import Qt, QEvent, QMargins, QUrl, QTimer
from PyQt6.QtGui import QPalette, QColor, QFont, QClipboard, QDesktopServices
from firebase_admin import credentials, firestore, initialize_app
import os
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
import numpy as np
from PyQt6.QtGui import QPixmap
from PyQt6.QtCore import QPropertyAnimation, QEasingCurve

def get_base_path():
    if getattr(sys, 'frozen', False):
        # If running as a PyInstaller bundle
        return sys._MEIPASS
    else:
        # If running as a normal Python script
        return os.path.dirname(os.path.abspath(__file__))

# Initialize Firebase
base_path = get_base_path()
json_path = os.path.join(base_path, "password_manager.json")
cred = credentials.Certificate(json_path)
initialize_app(cred)
db = firestore.client()
users_ref = db.collection("users")
credentials_ref = db.collection("credentials")


def encrypt_with_rsa(data, public_key):
    """Encrypt data with RSA public key using PKCS1_OAEP."""
    if isinstance(data, str):
        data = data.encode()
    rsa_key = RSA.import_key(public_key)
    cipher = PKCS1_OAEP.new(rsa_key)
    encrypted = cipher.encrypt(data)
    return base64.b64encode(encrypted).decode()


def decrypt_with_rsa(encrypted_data, private_key):
    """Decrypt data with RSA private key using PKCS1_OAEP."""
    try:
        data = base64.b64decode(encrypted_data)
        rsa_key = RSA.import_key(private_key)
        cipher = PKCS1_OAEP.new(rsa_key)
        decrypted = cipher.decrypt(data)
        return decrypted
    except Exception as e:
        print(f"RSA decryption failed: {str(e)}")
        return None


# Encryption/Decryption Functions
def encrypt_with_key(data, key):
    salt = get_random_bytes(16)
    derived_key = scrypt(key.encode() if isinstance(key, str) else key, salt, 32, N=2 ** 14, r=8, p=1)
    cipher = AES.new(derived_key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(data)
    return base64.b64encode(salt + cipher.nonce + tag + ciphertext).decode()


def decrypt_with_key(encrypted_data, key):
    try:
        data = base64.b64decode(encrypted_data)
        salt, iv, tag, ciphertext = data[:16], data[16:32], data[32:48], data[48:]
        derived_key = scrypt(key.encode() if isinstance(key, str) else key, salt, 32, N=2 ** 14, r=8, p=1)
        cipher = AES.new(derived_key, AES.MODE_GCM, nonce=iv)
        return cipher.decrypt_and_verify(ciphertext, tag)
    except ValueError as e:
        print(f"Decryption failed: {e}")
        return None


def encrypt_password(password, master_password, public_key):
    salt = get_random_bytes(16)
    key = scrypt(master_password.encode(), salt, 32, N=2 ** 14, r=8, p=1)
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
        face_bytes = face_encoding.tobytes()
        face_key = base64.b64encode(face_bytes).decode()
        user_data["face_recovery_key"] = encrypt_with_key(private_key, face_key)
        user_data["face_encoding"] = base64.b64encode(face_bytes).decode()
    if device_id is not None:
        user_data["device_recovery_key"] = encrypt_with_key(private_key, device_id)
    if trusted_contact_id:
        contact_doc = users_ref.document(trusted_contact_id).get()
        if contact_doc.exists:
            contact_public_key = contact_doc.to_dict()["public_key"]
            recovery_key = get_random_bytes(32)  # 32-byte recovery key
            user_data["contact_recovery_key"] = encrypt_with_key(private_key, recovery_key)
            # Use RSA to encrypt recovery key for trusted contact
            encrypted_recovery_key = encrypt_with_rsa(recovery_key, contact_public_key)
            print(
                f"Encrypting recovery key for {user_id} with {trusted_contact_id}'s public key: {contact_public_key[:20]}...")
            print(f"Storing encrypted key: {encrypted_recovery_key[:20]}... for {user_id} under {trusted_contact_id}")
            users_ref.document(trusted_contact_id).update({
                f"recovery_keys.{user_id}": encrypted_recovery_key
            })
            user_data["trusted_contact_id"] = trusted_contact_id
        else:
            print(f"Trusted contact {trusted_contact_id} not found.")

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

    if score <= 2:
        return "Weak", "#FF6B6B"
    elif score <= 4:
        return "Medium", "#FFD166"
    else:
        return "Strong", "#10B981"


# Main Window
class PasswordManagerWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("PassGuard")
        self.setGeometry(100, 100, 1000, 700)
        self.is_dark_mode = False

        # Central widget and main layout
        central_widget = QWidget(self)
        self.setCentralWidget(central_widget)
        self.main_layout = QHBoxLayout(central_widget)  # Changed to self.main_layout for consistency
        self.main_layout.setContentsMargins(0, 0, 0, 0)

        # Sidebar
        self.sidebar = QFrame()
        self.sidebar.setFixedWidth(250)
        sidebar_layout = QVBoxLayout(self.sidebar)
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

        # Add widgets to main layout
        self.main_layout.addWidget(self.sidebar)
        self.main_layout.addWidget(self.content, stretch=1)

        # Auto-Logout Timer
        self.inactivity_timer = QTimer(self)
        self.inactivity_timer.timeout.connect(self.logout)
        self.inactivity_timer.setInterval(300000)  # 5 minutes

        # Add floating developer bubble
        self.dev_bubble = QPushButton("👨‍💻", self)
        self.dev_bubble.setFixedSize(50, 50)
        self.dev_bubble.setStyleSheet("""
            QPushButton {
                background: #10B981;
                color: white;
                border-radius: 25px;
                border: none;
                font-size: 20px;
                box-shadow: 0 2px 4px rgba(0,0,0,0.2);
            }
            QPushButton:hover {
                background: #059669;
            }
        """)
        self.dev_bubble.move(self.width() - 70, self.height() - 70)
        self.dev_bubble.clicked.connect(self.show_dev_info)
        self.dev_bubble.setToolTip("Contact Developers")

        # Ensure bubble stays in position when window resizes
        self.resizeEvent = self.update_bubble_position

        # Initialize UI
        self.apply_theme()
        self.showFullScreen()
        self.installEventFilter(self)
        self.show_login()

    def apply_theme(self):
        if self.is_dark_mode:
            self.setStyleSheet("background: qlineargradient(x1:0, y1:0, x2:1, y2:1, stop:0 #2D2D2D, stop:1 #1A1A1A);")
            self.content.setStyleSheet("background: rgba(50, 50, 50, 0.95); border-radius: 12px;")
            self.sidebar.setStyleSheet("background: #fc6a03; border-radius: 10px;")
        else:
            self.setStyleSheet("background: qlineargradient(x1:0, y1:0, x2:1, y2:1, stop:0 #E0E7FF, stop:1 #FFFFFF);")
            self.content.setStyleSheet("background: rgba(255, 255, 255, 0.95); border-radius: 12px;")
            self.sidebar.setStyleSheet("background: #4A90E2; border-radius: 10px;")

    def toggle_theme(self):
        self.is_dark_mode = not self.is_dark_mode
        self.apply_theme()
        self.show_settings()

    def update_bubble_position(self, event):
        self.dev_bubble.move(self.width() - 70, self.height() - 70)
        super().resizeEvent(event)

    def show_dev_info(self):
        self.clear_content()

        # Title with gradient flair
        title = QLabel("Help & Support")
        title.setFont(QFont("Montserrat", 50, QFont.Weight.Bold))
        title.setStyleSheet(f"""
            color: {'#4A90E2' if not self.is_dark_mode else '#fc6a03'};
            padding: 5px 15px;
        """)
        self.content_layout.addWidget(title, alignment=Qt.AlignmentFlag.AlignCenter)

        # Container for everything
        help_container = QWidget()
        help_layout = QVBoxLayout(help_container)
        help_layout.setSpacing(20)

        # Developers Section
        dev_section = QFrame()
        dev_section.setStyleSheet(f"""
            background: {'#F9FAFB' if not self.is_dark_mode else '#313131'};
            border-radius: 10px;
            padding: 15px;
            box-shadow: 0 2px 6px rgba(0,0,0,0.1);
        """)
        dev_layout = QVBoxLayout(dev_section)
        dev_layout.setSpacing(15)
        dev_title = QLabel("MEET THINKTECH")
        dev_title.setFont(QFont("Montserrat", 18, QFont.Weight.Bold))
        dev_title.setStyleSheet(f"color: {'#333' if not self.is_dark_mode else '#E0E7FF'};")
        dev_layout.addWidget(dev_title, alignment=Qt.AlignmentFlag.AlignCenter)

        # ThinkTech Intro
        thinktech_intro = QLabel(
            "From vision to virtual, from dream to design—ThinkTech is the future, in every line.\n"
            "We don’t just think—we think tech."
        )
        thinktech_intro.setFont(QFont("Open Sans", 12, QFont.Weight.Medium))
        thinktech_intro.setStyleSheet(f"color: {'#555' if not self.is_dark_mode else '#B0B0B0'}; padding: 5px;")
        thinktech_intro.setAlignment(Qt.AlignmentFlag.AlignCenter)
        dev_layout.addWidget(thinktech_intro)

        # Developer 1
        dev1_frame = QFrame()
        dev1_layout = QHBoxLayout(dev1_frame)
        dev1_icon = QLabel("👨‍💻")
        dev1_icon.setFont(QFont("Open Sans", 30))
        dev1_icon.setStyleSheet(f"color: {'#4A90E2' if not self.is_dark_mode else '#fc6a03'};")
        dev1_layout.addWidget(dev1_icon)
        dev1_info = QLabel("Apoorv Gupta")
        dev1_info.setFont(QFont("Open Sans", 16, QFont.Weight.Medium))
        dev1_info.setStyleSheet(f"color: {'#333' if not self.is_dark_mode else '#E0E7FF'};")
        dev1_layout.addWidget(dev1_info)
        dev1_btn = QPushButton("📎 LinkedIn")
        dev1_btn.setFont(QFont("Montserrat", 12, QFont.Weight.Bold))
        dev1_btn.setStyleSheet("""
            QPushButton {
                background: #0A66C2;
                color: white;
                padding: 6px 15px;
                border-radius: 5px;
                border: none;
                box-shadow: 0 1px 3px rgba(0,0,0,0.1);
                transition: transform 0.2s;
            }
            QPushButton:hover {
                background: #004182;
                transform: scale(1.05);
            }
        """)
        dev1_btn.clicked.connect(lambda: QDesktopServices.openUrl(QUrl("https://www.linkedin.com/in/-apoorv-/")))
        dev1_btn.setToolTip("Connect with Apoorv on LinkedIn")
        dev1_layout.addWidget(dev1_btn)
        dev_layout.addWidget(dev1_frame)

        # Developer 2
        dev2_frame = QFrame()
        dev2_layout = QHBoxLayout(dev2_frame)
        dev2_icon = QLabel("👨‍💻")
        dev2_icon.setFont(QFont("Open Sans", 30))
        dev2_icon.setStyleSheet(f"color: {'#4A90E2' if not self.is_dark_mode else '#fc6a03'};")
        dev2_layout.addWidget(dev2_icon)
        dev2_info = QLabel("Yash Verdhan")
        dev2_info.setFont(QFont("Open Sans", 16, QFont.Weight.Medium))
        dev2_info.setStyleSheet(f"color: {'#333' if not self.is_dark_mode else '#E0E7FF'};")
        dev2_layout.addWidget(dev2_info)
        dev2_btn = QPushButton("📎 LinkedIn")
        dev2_btn.setFont(QFont("Montserrat", 12, QFont.Weight.Bold))
        dev2_btn.setStyleSheet("""
            QPushButton {
                background: #0A66C2;
                color: white;
                padding: 6px 15px;
                border-radius: 5px;
                border: none;
                box-shadow: 0 1px 3px rgba(0,0,0,0.1);
                transition: transform 0.2s;
            }
            QPushButton:hover {
                background: #004182;
                transform: scale(1.05);
            }
        """)
        dev2_btn.clicked.connect(lambda: QDesktopServices.openUrl(QUrl("https://www.linkedin.com/in/yash-verdhan")))
        dev2_btn.setToolTip("Connect with Yash on LinkedIn")
        dev2_layout.addWidget(dev2_btn)
        dev_layout.addWidget(dev2_frame)
        help_layout.addWidget(dev_section)

        # FAQ Section
        faq_section = QFrame()
        faq_section.setStyleSheet(f"""
            background: {'#F9FAFB' if not self.is_dark_mode else '#313131'};
            border-radius: 10px;
            padding: 15px;
            box-shadow: 0 2px 6px rgba(0,0,0,0.1);
        """)
        faq_layout = QVBoxLayout(faq_section)
        faq_title = QLabel("Frequently Asked Questions")
        faq_title.setFont(QFont("Montserrat", 18, QFont.Weight.Bold))
        faq_title.setStyleSheet(f"color: {'#333' if not self.is_dark_mode else '#E0E7FF'}; padding-bottom: 10px;")
        faq_layout.addWidget(faq_title, alignment=Qt.AlignmentFlag.AlignCenter)

        # Updated FAQs with Founder Mention and Security
        faqs = [
            ("Who is ThinkTech?",
             "ThinkTech is the brainchild of founder Apoorv Gupta, turning visions into virtual reality and dreams into designs. "
             "From vision to virtual, from dream to design—ThinkTech is the future, in every line. In every code we write, "
             "in every algorithm we create, we unlock new possibilities. We don’t just think—we think tech."),
            ("How do I reset my master password?",
             "Head to 'Forgot Password?' on the login screen, pick 'Face Scan', 'Device Fingerprint', or 'Trusted Contact', "
             "and follow the steps to set a new password. ThinkTech’s got your back!"),
            ("What if my face scan fails?",
             "Ensure good lighting and face the camera straight on. If it’s still not working, switch to another recovery "
             "option like Device Fingerprint or Trusted Contact—our tech adapts to you."),
            ("How do I add a new credential?",
             "Log in, hit 'Add Credential', enter the website, username, password, and category, then click 'Save'. "
             "It’s that simple with ThinkTech’s intuitive design!"),
            ("How does PassGuard keep my data safe?",
             "Your data’s locked down with top-tier encryption: AES-256 for passwords and RSA for key protection. "
             "In every code we write at ThinkTech, we prioritize your security—stored safely in Firebase."),
            ("What’s AES and RSA encryption?",
             "AES-256 is a super-strong symmetric cipher that scrambles your passwords with your master password. "
             "RSA uses a public-private key pair to secure your private key. Together, they’re the backbone of PassGuard’s "
             "unbreakable security, crafted by ThinkTech."),
            ("Can I trust Firebase with my data?",
             "Absolutely! Firebase is a secure, Google-backed cloud platform. Paired with ThinkTech’s AES and RSA encryption, "
             "your data stays untouchable—even we can’t peek inside!"),
            ("How do I set up a trusted contact?",
             "During setup, enter a friend’s username in the 'Trusted Contact' field. They’ll get a unique 44-character recovery "
             "key in their Settings page, encrypted with their public key. They can share it with you securely (e.g., in person "
             "or via encrypted chat) if you need to recover your account."),
            ("How do I use a trusted contact to recover my account?",
             "Ask your trusted contact to log in, go to Settings, and copy their recovery key for your username. Then, in "
             "'Forgot Password?', select 'Trusted Contact', paste that 44-character key, and submit—it’ll unlock your account."),
            ("How do I contact support?",
             "Hit the LinkedIn buttons above to reach the ThinkTech crew directly. We’re here to help unlock any possibility!")
        ]

        for question, answer in faqs:
            q_btn = QPushButton(f"❓ {question}")
            q_btn.setFont(QFont("Open Sans", 14))
            q_btn.setStyleSheet(f"""
                QPushButton {{
                    background: {'#E0E7FF' if not self.is_dark_mode else '#3A3A3A'};
                    color: {'#333' if not self.is_dark_mode else '#E0E7FF'};
                    padding: 10px;
                    border-radius: 5px;
                    text-align: left;
                    border: none;
                    box-shadow: 0 1px 3px rgba(0,0,0,0.1);
                    transition: transform 0.2s;
                }}
                QPushButton:hover {{
                    background: {'#D1D9FF' if not self.is_dark_mode else '#4A4A4A'};
                    transform: scale(1.02);
                }}
            """)
            q_btn.setCursor(Qt.CursorShape.PointingHandCursor)

            a_label = QLabel(answer)
            a_label.setFont(QFont("Open Sans", 12))
            a_label.setStyleSheet(f"color: {'#555' if not self.is_dark_mode else '#B0B0B0'}; padding: 5px 15px;")
            a_label.setWordWrap(True)
            a_label.hide()

            q_btn.clicked.connect(lambda checked, btn=q_btn, lbl=a_label: self.toggle_faq(btn, lbl))
            faq_layout.addWidget(q_btn)
            faq_layout.addWidget(a_label)

        help_layout.addWidget(faq_section)

        # Back Button with icon and hover effect
        back_btn = QPushButton("⬅️ Back")
        back_btn.setFont(QFont("Montserrat", 12, QFont.Weight.Bold))
        back_btn.setStyleSheet("""
            QPushButton {
                background: #4A90E2;
                color: white;
                padding: 8px 20px;
                border-radius: 5px;
                border: none;
                box-shadow: 0 2px 4px rgba(0,0,0,0.15);
                transition: transform 0.2s;
            }
            QPushButton:hover {
                background: #357ABD;
                transform: scale(1.05);
            }
        """)
        back_btn.clicked.connect(self.show_settings if hasattr(self, 'user_id') and self.user_id else self.show_login)
        back_btn.setToolTip("Return to previous screen")
        help_layout.addWidget(back_btn, alignment=Qt.AlignmentFlag.AlignCenter)

        # Scrollable Area
        from PyQt6.QtWidgets import QScrollArea
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setWidget(help_container)
        scroll.setStyleSheet(f"""
            QScrollArea {{
                background: {'#FFFFFF' if not self.is_dark_mode else '#2D2D2D'};
                border: none;
                border-radius: 10px;
            }}
            QScrollBar:vertical {{
                border: none;
                background: {'#E0E7FF' if not self.is_dark_mode else '#3A3A3A'};
                width: 10px;
                margin: 0px 0px 0px 0px;
                border-radius: 5px;
            }}
            QScrollBar::handle:vertical {{
                background: {'#4A90E2' if not self.is_dark_mode else '#fc6a03'};
                border-radius: 5px;
            }}
        """)
        self.content_layout.addWidget(scroll, stretch=1)

    def toggle_faq(self, button, label):
        """Toggle FAQ answer visibility"""
        if label.isVisible():
            label.hide()
            button.setStyleSheet(f"""
                background: {'#E0E7FF' if not self.is_dark_mode else '#3A3A3A'};
                color: {'#333' if not self.is_dark_mode else '#E0E7FF'};
                padding: 10px;
                border-radius: 5px;
                text-align: left;
            """)
        else:
            label.show()
            button.setStyleSheet(f"""
                background: {'#4A90E2' if not self.is_dark_mode else '#fc6a03'};
                color: white;
                padding: 10px;
                border-radius: 5px;
                text-align: left;
            """)

    def show_settings(self):
        self.clear_content()
        self.content_layout.setSpacing(20)  # Tightened from 25 for a cozier feel

        # Title with gradient flair
        title = QLabel("Settings")
        title.setFont(QFont("Montserrat", 48, QFont.Weight.Bold))
        title.setStyleSheet(f"""
            color: {'#4A90E2' if not self.is_dark_mode else '#fc6a03'};

            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            padding: 5px 20px;
        """)
        self.content_layout.addWidget(title, alignment=Qt.AlignmentFlag.AlignCenter)

        # Account section with a sleek frame
        account_frame = QFrame()
        account_frame.setStyleSheet(f"""
            background: {'#FFFFFF' if not self.is_dark_mode else '#313131'};
            border-radius: 12px;
            box-shadow: 0 3px 8px rgba(0,0,0,0.1);
            padding: 15px;
            margin: 5px 0;  # Tightened from 10px
        """)
        account_layout = QHBoxLayout(account_frame)
        account_icon = QLabel("👤")
        account_icon.setFont(QFont("Open Sans", 50))
        account_icon.setStyleSheet(f"color: {'#4A90E2' if not self.is_dark_mode else '#fc6a03'};")
        account_layout.addWidget(account_icon)
        account_label = QLabel(f"{self.user_id}")
        account_label.setFont(QFont("Open Sans", 38, QFont.Weight.Medium))
        account_label.setStyleSheet(f"color: {'#333' if not self.is_dark_mode else '#E0E7FF'};")
        account_layout.addWidget(account_label)
        self.content_layout.addWidget(account_frame, alignment=Qt.AlignmentFlag.AlignCenter)

        # Recovery Keys section with a subtle background
        doc = users_ref.document(self.user_id).get()
        print(f"User ID: {self.user_id}, Doc exists: {doc.exists}")
        recovery_keys = doc.to_dict().get("recovery_keys", {})
        print(f"Raw recovery keys: {recovery_keys}")

        if recovery_keys and hasattr(self, 'private_key') and self.private_key:
            keys_frame = QFrame()
            keys_frame.setStyleSheet(f"""
                background: {'#E0E7FF' if not self.is_dark_mode else '#3A3A3A'};
                border-radius: 10px;
                padding: 15px;
                box-shadow: 0 2px 6px rgba(0,0,0,0.05);
                margin: 5px 0;  # Tightened from 10px
            """)
            keys_layout = QVBoxLayout(keys_frame)
            keys_label = QLabel("Your Recovery Keys (Share with friends if needed):")
            keys_label.setFont(QFont("Open Sans", 14, QFont.Weight.Bold))
            keys_label.setStyleSheet(f"color: {'#333' if not self.is_dark_mode else '#E0E7FF'}; padding-bottom: 8px;")
            keys_layout.addWidget(keys_label)

            for requester_id, encrypted_key in recovery_keys.items():
                print(
                    f"Decrypting key for {requester_id}: {encrypted_key[:20]}... with private key: {self.private_key[:20]}...")
                recovery_key = decrypt_with_rsa(encrypted_key, self.private_key)
                if recovery_key:
                    key_str = base64.b64encode(recovery_key).decode()
                    print(f"Decrypted key for {requester_id}: {key_str}")
                    key_frame = QFrame()
                    key_frame.setStyleSheet(f"""
                        background: {'#FFFFFF' if not self.is_dark_mode else '#4A4A4A'};
                        border-radius: 8px;
                        padding: 10px;
                        margin: 3px 0;  # Tightened from 5px
                    """)
                    key_layout = QHBoxLayout(key_frame)
                    key_text = QLabel(f"For {requester_id}: {key_str}")
                    key_text.setFont(QFont("Open Sans", 11))
                    key_text.setStyleSheet(f"color: {'#555' if not self.is_dark_mode else '#B0B0B0'};")
                    key_layout.addWidget(key_text)
                    copy_btn = QPushButton("Copy")
                    copy_btn.setFont(QFont("Montserrat", 10, QFont.Weight.Bold))
                    copy_btn.setStyleSheet("""
                        background: #10B981; 
                        color: white; 
                        padding: 6px 15px; 
                        border-radius: 5px;
                        border: none;
                        box-shadow: 0 1px 3px rgba(0,0,0,0.1);
                    """)
                    copy_btn.clicked.connect(lambda checked, k=key_str: QApplication.clipboard().setText(k))
                    key_layout.addWidget(copy_btn)
                    keys_layout.addWidget(key_frame)
                else:
                    print(f"Failed to decrypt key for {requester_id}")
                    error_label = QLabel(f"Couldn’t decrypt key for {requester_id}")
                    error_label.setFont(QFont("Open Sans", 10))
                    error_label.setStyleSheet(f"color: {'#FF6B6B' if not self.is_dark_mode else '#FF8787'};")
                    keys_layout.addWidget(error_label)
            self.content_layout.addWidget(keys_frame, alignment=Qt.AlignmentFlag.AlignCenter)
        else:
            no_keys_label = QLabel("No recovery keys available yet.")
            no_keys_label.setFont(QFont("Open Sans", 12, QFont.Weight.Medium))
            no_keys_label.setStyleSheet(f"color: {'#888' if not self.is_dark_mode else '#A0A0A0'}; padding: 8px;")
            self.content_layout.addWidget(no_keys_label, alignment=Qt.AlignmentFlag.AlignCenter)

        # Buttons section with icons and hover scale effect at the bottom
        theme_btn = QPushButton(f"🌙 Switch to {'Dark' if not self.is_dark_mode else 'Light'} Mode")
        theme_btn.setFont(QFont("Montserrat", 14, QFont.Weight.Bold))
        theme_btn.setStyleSheet("""
            QPushButton {
                background: #4A90E2;
                color: white;
                padding: 12px 30px;
                border-radius: 8px;
                border: none;
                box-shadow: 0 2px 6px rgba(0,0,0,0.15);
                transition: transform 0.2s;
            }
            QPushButton:hover {
                background: #357ABD;
                transform: scale(1.05);
            }
        """)
        theme_btn.clicked.connect(self.toggle_theme)
        self.content_layout.addWidget(theme_btn, alignment=Qt.AlignmentFlag.AlignCenter)

        logout_btn = QPushButton("🚪 Logout")
        logout_btn.setFont(QFont("Montserrat", 14, QFont.Weight.Bold))
        logout_btn.setStyleSheet("""
            QPushButton {
                background: #FF6B6B;
                color: white;
                padding: 12px 30px;
                border-radius: 8px;
                border: none;
                box-shadow: 0 2px 6px rgba(0,0,0,0.15);
                transition: transform 0.2s;
            }
            QPushButton:hover {
                background: #E55A5A;
                transform: scale(1.05);
            }
        """)
        logout_btn.setToolTip("Log out of your account")
        logout_btn.clicked.connect(self.logout)
        self.content_layout.addWidget(logout_btn, alignment=Qt.AlignmentFlag.AlignCenter)

        contact_btn = QPushButton("📞 Contact Developer")
        contact_btn.setFont(QFont("Montserrat", 14, QFont.Weight.Bold))
        contact_btn.setStyleSheet("""
            QPushButton {
                background: #10B981;
                color: white;
                padding: 12px 30px;
                border-radius: 8px;
                border: none;
                box-shadow: 0 2px 6px rgba(0,0,0,0.15);
                transition: transform 0.2s;
            }
            QPushButton:hover {
                background: #059669;
                transform: scale(1.05);
            }
        """)
        contact_btn.clicked.connect(lambda: QDesktopServices.openUrl(QUrl("https://www.linkedin.com/in/-apoorv-/")))
        contact_btn.setToolTip("Reach out to the developer")
        self.content_layout.addWidget(contact_btn, alignment=Qt.AlignmentFlag.AlignCenter)

        about_btn = QPushButton("ℹ️ About PassGuard")
        about_btn.setFont(QFont("Montserrat", 14, QFont.Weight.Bold))
        about_btn.setStyleSheet("""
            QPushButton {
                background: #6B7280;
                color: white;
                padding: 12px 30px;
                border-radius: 8px;
                border: none;
                box-shadow: 0 2px 6px rgba(0,0,0,0.15);
                transition: transform 0.2s;
            }
            QPushButton:hover {
                background: #4B5563;
                transform: scale(1.05);
            }
        """)
        about_btn.clicked.connect(self.show_about)
        about_btn.setToolTip("Learn more about PassGuard")
        self.content_layout.addWidget(about_btn, alignment=Qt.AlignmentFlag.AlignCenter)

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
        # Delete all widgets
        for widget in self.content.findChildren(QWidget):
            widget.deleteLater()
        # Remove all stretch items from the layout
        for i in reversed(range(self.content_layout.count())):
            item = self.content_layout.itemAt(i)
            if item.spacerItem():  # Check if the item is a stretch (spacer)
                self.content_layout.removeItem(item)

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
        self.content_layout.setSpacing(20)

        # Create a container to group title and login frame
        container = QFrame()
        container.setObjectName("loginContainer")  # For animation
        container_layout = QVBoxLayout(container)
        container_layout.setSpacing(10)

        # Title with gradient flair
        title = QLabel("Welcome Back")
        title.setFont(QFont("Montserrat", 50, QFont.Weight.Bold))
        title.setStyleSheet(f"""
            color: {'#4A90E2' if not self.is_dark_mode else '#fc6a03'};
            padding: 5px 15px;
        """)
        container_layout.addWidget(title, alignment=Qt.AlignmentFlag.AlignCenter)

        # Frame for all login elements
        login_frame = QFrame()
        login_frame.setFixedWidth(400)
        login_frame.setFixedHeight(600)  # Slightly reduced height for better balance
        login_frame.setStyleSheet(f"""
            background: {'#F9FAFB' if not self.is_dark_mode else '#3A3A3A'};
            border-radius: 15px;
            padding: 20px;
            box-shadow: 0 4px 12px rgba(0,0,0,0.15);
        """)
        login_layout = QVBoxLayout(login_frame)
        login_layout.setSpacing(25)  # Increased spacing for better breathing room

        # Input fields with icons
        self.entries = {}
        for label, key, echo, placeholder, icon in [
            ("Username", "username", QLineEdit.EchoMode.Normal, "Enter your username", "👤"),
            ("Master Password", "password", QLineEdit.EchoMode.Password, "Enter your master password", "🔒")
        ]:
            input_frame = QFrame()
            input_frame.setStyleSheet(f"""
                background: {'#FFFFFF' if not self.is_dark_mode else '#4A4A4A'};
                border: 1px solid {'#E0E7FF' if not self.is_dark_mode else '#5A5A5A'};
                border-radius: 8px;
                padding: 5px;
                box-shadow: 0 1px 3px rgba(0,0,0,0.1);
            """)
            input_layout = QHBoxLayout(input_frame)

            # Icon
            icon_label = QLabel(icon)
            icon_label.setFont(QFont("Open Sans", 20))
            icon_label.setStyleSheet(f"color: {'#4A90E2' if not self.is_dark_mode else '#fc6a03'}; padding: 0 10px;")
            input_layout.addWidget(icon_label)

            # Label and Entry
            input_sub_layout = QVBoxLayout()
            lbl = QLabel(label)
            lbl.setFont(QFont("Open Sans", 12))
            lbl.setStyleSheet(f"color: {'#333' if not self.is_dark_mode else '#E0E7FF'};")
            input_sub_layout.addWidget(lbl)

            entry = QLineEdit()
            entry.setFont(QFont("Open Sans", 14))
            entry.setStyleSheet(f"""
                background: {'#FFFFFF' if not self.is_dark_mode else '#4A4A4A'}; 
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
            input_sub_layout.addWidget(entry)
            input_layout.addLayout(input_sub_layout)

            login_layout.addWidget(input_frame)
            self.entries[key] = entry

        # Add stretch to position buttons lower
        login_layout.addStretch(1)

        # Button group in a sub-layout
        button_frame = QFrame()
        button_layout = QVBoxLayout(button_frame)
        button_layout.setSpacing(35)

        # Login Button with icon and hover effect
        login_btn = QPushButton("🚀 Login")
        login_btn.setFont(QFont("Montserrat", 16, QFont.Weight.Bold))
        login_btn.setMinimumHeight(40)
        login_btn.setStyleSheet("""
            QPushButton {
                background: #4A90E2; 
                color: white; 
                padding: 0px 30px; 
                border-radius: 8px;
                border: none;
                box-shadow: 0 2px 6px rgba(0,0,0,0.15);
                transition: transform 0.2s;
            }
            QPushButton:hover {
                background: #357ABD;
                transform: scale(1.05);
            }
        """)
        login_btn.clicked.connect(self.login)
        login_btn.setToolTip("Log in to your account")
        button_layout.addWidget(login_btn, alignment=Qt.AlignmentFlag.AlignCenter)

        # Forgot Password Button with icon and hover effect
        forgot_btn = QPushButton("❓ Forgot Password?")
        forgot_btn.setFont(QFont("Montserrat", 12, QFont.Weight.Bold))
        forgot_btn.setMinimumHeight(40)
        forgot_btn.setStyleSheet("""
            QPushButton {
                background: #FFD166; 
                color: #333333; 
                padding: 8px 20px; 
                border-radius: 5px;
                border: none;
                box-shadow: 0 2px 4px rgba(0,0,0,0.15);
                transition: transform 0.2s;
            }
            QPushButton:hover {
                background: #FFC107;
                transform: scale(1.05);
            }
        """)
        forgot_btn.clicked.connect(self.show_recovery_options)
        forgot_btn.setToolTip("Recover your account")
        button_layout.addWidget(forgot_btn, alignment=Qt.AlignmentFlag.AlignCenter)

        login_layout.addWidget(button_frame, alignment=Qt.AlignmentFlag.AlignCenter)

        # PassGuard Logo Image
        logo_label = QLabel()
        logo_path = os.path.join(get_base_path(), "logo.png")
        logo_pixmap = QPixmap(logo_path)
        if not logo_pixmap.isNull():
            logo_pixmap = logo_pixmap.scaled(200, 200, Qt.AspectRatioMode.KeepAspectRatio,
                                             Qt.TransformationMode.SmoothTransformation)
            logo_label.setPixmap(logo_pixmap)
        else:
            logo_label.setText("PassGuard Logo")
            logo_label.setFont(QFont("Montserrat", 16, QFont.Weight.Bold))
            logo_label.setStyleSheet(f"color: {'#4A90E2' if not self.is_dark_mode else '#fc6a03'};")
        logo_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        login_layout.addWidget(logo_label, alignment=Qt.AlignmentFlag.AlignCenter)

        login_layout.addStretch(1)

        container_layout.addWidget(login_frame, alignment=Qt.AlignmentFlag.AlignCenter)

        self.content_layout.addStretch(2)
        self.content_layout.addWidget(container, alignment=Qt.AlignmentFlag.AlignCenter)
        self.content_layout.addStretch(1)

        # Add fade-in animation

        animation = QPropertyAnimation(container, b"windowOpacity", self)
        animation.setDuration(1000)  # 1 second
        animation.setStartValue(0.0)
        animation.setEndValue(1.0)
        animation.setEasingCurve(QEasingCurve.Type.InOutQuad)
        animation.start()

    def show_recovery_options(self):
        self.clear_content()
        self.content_layout.setSpacing(20)  # Consistent spacing like other pages

        # Title with gradient flair
        title = QLabel("Recover Your Account")
        title.setFont(QFont("Montserrat", 60, QFont.Weight.Bold))
        title.setStyleSheet(f"""
            color: {'#4A90E2' if not self.is_dark_mode else '#fc6a03'};
            padding: 5px 15px;
        """)
        self.content_layout.addWidget(title, alignment=Qt.AlignmentFlag.AlignCenter)

        # Container for recovery options
        container = QFrame()
        container.setStyleSheet(f"""
            background: {'#F9FAFB' if not self.is_dark_mode else '#3A3A3A'};
            border-radius: 15px;
            padding: 20px;
            box-shadow: 0 4px 12px rgba(0,0,0,0.15);
        """)
        container_layout = QVBoxLayout(container)
        container_layout.setSpacing(0)

        user_id = self.entries["username"].text() if hasattr(self, 'entries') and "username" in self.entries else ""
        if not user_id:
            error_frame = QFrame()
            error_frame.setStyleSheet(f"""
                background: {'#FFF1F1' if not self.is_dark_mode else '#4A2A2A'};
                border-radius: 8px;
                padding: 10px;
                box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            """)
            error_layout = QVBoxLayout(error_frame)
            error = QLabel("Please enter your username first.")
            error.setFont(QFont("Open Sans", 12))
            error.setStyleSheet("color: #FF6B6B;")
            error.setAlignment(Qt.AlignmentFlag.AlignCenter)
            error_layout.addWidget(error)
            container_layout.addWidget(error_frame, alignment=Qt.AlignmentFlag.AlignCenter)
        else:
            options = [
                ("😀 Face Scan", lambda: self.recover_with_face(user_id), "Use your webcam to scan your face"),
                ("📱 Device Fingerprint", lambda: self.recover_with_device(user_id), "Verify using this device"),
                ("👥 Trusted Contact", lambda: self.recover_with_contact(user_id), "Enter key from trusted contact")
            ]
            for text, cmd, desc in options:
                btn_frame = QFrame()
                btn_layout = QVBoxLayout(btn_frame)
                btn_layout.setSpacing(5)

                # Recovery option button with icon and hover effect
                btn = QPushButton(text)
                btn.setFont(QFont("Montserrat", 14, QFont.Weight.Bold))
                btn.setStyleSheet("""
                    QPushButton {
                        background: #10B981; 
                        color: white; 
                        padding: 10px 20px; 
                        border-radius: 5px;
                        border: none;
                        box-shadow: 0 2px 4px rgba(0,0,0,0.15);
                        transition: transform 0.2s;
                    }
                    QPushButton:hover {
                        background: #059669;
                        transform: scale(1.05);
                    }
                """)
                btn.clicked.connect(cmd)
                btn.setToolTip(desc)
                btn_layout.addWidget(btn)

                desc_label = QLabel(desc)
                desc_label.setFont(QFont("Open Sans", 10))
                desc_label.setStyleSheet(f"color: {'#555' if not self.is_dark_mode else '#B0B0B0'};")
                desc_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
                btn_layout.addWidget(desc_label)

                container_layout.addWidget(btn_frame, alignment=Qt.AlignmentFlag.AlignCenter)

        # Add the container to the main layout with stretch for centering
        self.content_layout.addStretch(1)
        self.content_layout.addWidget(container, alignment=Qt.AlignmentFlag.AlignCenter)
        self.content_layout.addStretch(1)

        # Back Button with icon and hover effect
        back_btn = QPushButton("⬅️ Back")
        back_btn.setFont(QFont("Montserrat", 12, QFont.Weight.Bold))
        back_btn.setStyleSheet(f"""
            QPushButton {{
                background: {'#4A90E2' if not self.is_dark_mode else '#fc6a03'};
                color: white;
                padding: 8px 20px;
                border-radius: 5px;
                border: none;
                box-shadow: 0 2px 4px rgba(0,0,0,0.15);
                transition: transform 0.2s;
            }}
            QPushButton:hover {{
                background: {'#357ABD' if not self.is_dark_mode else '#e55a02'};
                transform: scale(1.05);
            }}
        """)
        back_btn.clicked.connect(self.show_login)
        back_btn.setToolTip("Return to login screen")
        self.content_layout.addWidget(back_btn, alignment=Qt.AlignmentFlag.AlignCenter)

    def recover_with_face(self, user_id):
        print(f"Starting face recovery for user: {user_id}")
        doc = users_ref.document(user_id).get()
        if not doc.exists or "face_recovery_key" not in doc.to_dict():
            self.show_error("Face scan not set up for this user.")
            return

        face_encoding = self.capture_face()
        if face_encoding is None:
            self.show_error("Failed to capture face. Ensure webcam is connected and face is visible.")
            return

        try:
            # Load stored face encoding
            stored_encoding_bytes = base64.b64decode(doc.to_dict()["face_encoding"])
            stored_encoding = np.frombuffer(stored_encoding_bytes, dtype=np.float64)
            print(f"Stored encoding shape: {stored_encoding.shape}, sample: {stored_encoding[:5]}")
            print(f"New encoding shape: {face_encoding.shape}, sample: {face_encoding[:5]}")

            # Compare faces
            match = face_recognition.compare_faces([stored_encoding], face_encoding, tolerance=0.6)[0]
            print(f"Face match result: {match}")

            if match:
                # Use the *stored* face encoding bytes as the key (exact match)
                face_key = base64.b64encode(stored_encoding_bytes).decode()
                print(f"Decrypting with face_key: {face_key[:10]}...")
                private_key = decrypt_with_key(doc.to_dict()["face_recovery_key"], face_key)
                if private_key is None:
                    self.show_error("Decryption failed. Stored key mismatch.")
                    return
                print("Private key decrypted successfully!")
                self.reset_master_password(user_id, private_key)
            else:
                self.show_error("Face does not match.")
        except Exception as e:
            print(f"Error in face recovery: {str(e)}")
            self.show_error(f"Face recovery failed: {str(e)}")

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
        title.setStyleSheet(f"color: {'#4A90E2' if not self.is_dark_mode else '#fc6a03'};")
        self.content_layout.addWidget(title, alignment=Qt.AlignmentFlag.AlignCenter)

        lbl = QLabel("Enter the recovery key from your trusted contact:")
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
        key_entry.setPlaceholderText("Paste the 44-character recovery key here")
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
        try:
            # Convert base64 back to bytes (since trusted contact provides base64 string)
            recovery_key_bytes = base64.b64decode(contact_key)
            private_key = decrypt_with_key(doc.to_dict()["contact_recovery_key"], recovery_key_bytes)
            if private_key:
                self.reset_master_password(user_id, private_key)
            else:
                self.show_error("Invalid recovery key.")
        except Exception as e:
            self.show_error(f"Error verifying key: {str(e)}")

    def reset_master_password(self, user_id, private_key):
        self.clear_content()
        title = QLabel("Reset Master Password")
        title.setFont(QFont("Montserrat", 30, QFont.Weight.Bold))
        title.setStyleSheet(f"color: {'#4A90E2' if not self.is_dark_mode else '#fc6a03'};")
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
        save_btn.clicked.connect(
            lambda: self.save_new_password(user_id, private_key, new_pass.text(), confirm_pass.text()))
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
        print("Opening webcam for face capture...")
        cap = cv2.VideoCapture(0)
        if not cap.isOpened():
            print("Error: Could not open webcam.")
            return None

        for _ in range(10):  # Try multiple frames
            ret, frame = cap.read()
            if not ret:
                print("Error: Could not read frame.")
                cap.release()
                return None

            rgb_frame = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
            encodings = face_recognition.face_encodings(rgb_frame)
            if encodings:
                print("Face detected and encoded successfully.")
                cap.release()
                return encodings[0]

        print("No face detected after multiple attempts.")
        cap.release()
        return None

    def get_device_id(self):
        return str(uuid.getnode()) + str(psutil.disk_partitions()[0].device if psutil.disk_partitions() else "default")

    def prompt_setup_recovery(self):
        self.clear_content()
        title = QLabel("Set Up Recovery Options")
        title.setFont(QFont("Montserrat", 30, QFont.Weight.Bold))
        title.setStyleSheet(f"color: {'#4A90E2' if not self.is_dark_mode else '#fc6a03'};")
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

    def toggle_theme(self):
        self.is_dark_mode = not self.is_dark_mode
        self.apply_theme()
        self.show_settings()

    def show_about(self):
        self.clear_content()
        title = QLabel("About PassGuard")
        title.setFont(QFont("Montserrat", 30, QFont.Weight.Bold))
        title.setStyleSheet(f"color: {'#4A90E2' if not self.is_dark_mode else '#fc6a03'};")
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
        title.setStyleSheet(f"color: {'#4A90E2' if not self.is_dark_mode else '#fc6a03'};")
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
        title.setStyleSheet(f"color: {'#4A90E2' if not self.is_dark_mode else '#fc6a03'};")
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

        # Generate Password Button with icon and hover effect
        generate_btn = QPushButton("🎲 Generate Password")
        generate_btn.setFont(QFont("Montserrat", 12, QFont.Weight.Bold))
        generate_btn.setStyleSheet("""
            QPushButton {
                background: #10B981; 
                color: white; 
                padding: 8px 20px; 
                border-radius: 5px;
                border: none;
                box-shadow: 0 2px 4px rgba(0,0,0,0.15);
                transition: transform 0.2s;
            }
            QPushButton:hover {
                background: #059669;
                transform: scale(1.05);
            }
        """)
        generate_btn.clicked.connect(lambda: [entries["password"].setText(generate_password()), update_strength()])
        generate_btn.setToolTip("Generate a strong random password")
        self.content_layout.addWidget(generate_btn, alignment=Qt.AlignmentFlag.AlignCenter)

        # Save Button with icon and hover effect
        save_btn = QPushButton("💾 Save")
        save_btn.setFont(QFont("Montserrat", 16, QFont.Weight.Bold))
        save_btn.setStyleSheet("""
            QPushButton {
                background: #4A90E2; 
                color: white; 
                padding: 10px 30px; 
                border-radius: 8px;
                border: none;
                box-shadow: 0 2px 4px rgba(0,0,0,0.15);
                transition: transform 0.2s;
            }
            QPushButton:hover {
                background: #357ABD;
                transform: scale(1.05);
            }
        """)
        save_btn.clicked.connect(lambda: self.store_credential(entries))
        save_btn.setToolTip("Save the credential")
        self.content_layout.addWidget(save_btn, alignment=Qt.AlignmentFlag.AlignCenter)

    def show_view_credentials(self):
        self.clear_content()
        title = QLabel("View Credentials")
        title.setFont(QFont("Montserrat", 30, QFont.Weight.Bold))
        title.setStyleSheet(f"color: {'#4A90E2' if not self.is_dark_mode else '#fc6a03'};")
        self.content_layout.addWidget(title, alignment=Qt.AlignmentFlag.AlignCenter)

        # Search and Filter Container
        filter_frame = QFrame()
        filter_frame.setStyleSheet(f"""
            background: {'#F9FAFB' if not self.is_dark_mode else '#3A3A3A'};
            border-radius: 10px;
            padding: 10px;
            box-shadow: 0 2px 6px rgba(0,0,0,0.1);
        """)
        filter_layout = QHBoxLayout(filter_frame)
        filter_layout.setSpacing(10)

        search_bar = QLineEdit()
        search_bar.setFont(QFont("Open Sans", 14))
        search_bar.setStyleSheet(f"""
            background: {'#FFFFFF' if not self.is_dark_mode else '#4A4A4A'}; 
            border: 1px solid {'#E0E7FF' if not self.is_dark_mode else '#5A5A5A'};
            padding: 8px; 
            border-radius: 5px; 
            color: {'#333' if not self.is_dark_mode else '#E0E7FF'};
        """)
        search_bar.setPlaceholderText("Search by website or username...")
        palette = search_bar.palette()
        palette.setColor(QPalette.ColorRole.PlaceholderText, QColor("#888"))
        search_bar.setPalette(palette)
        filter_layout.addWidget(search_bar)

        category_filter = QComboBox()
        category_filter.setFont(QFont("Open Sans", 12))
        category_filter.setStyleSheet(f"""
            background: {'#FFFFFF' if not self.is_dark_mode else '#4A4A4A'}; 
            border: 1px solid {'#E0E7FF' if not self.is_dark_mode else '#5A5A5A'};
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
        filter_layout.addWidget(category_filter)

        self.content_layout.addWidget(filter_frame)

        credential_list = QListWidget()
        credential_list.setFont(QFont("Open Sans", 12))
        credential_list.setStyleSheet(f"""
            background: {'#E0E7FF' if not self.is_dark_mode else '#3A3A3A'}; 
            border: none; 
            padding: 10px; 
            border-radius: 5px;
        """)
        credential_list.setSpacing(8)
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
                    widget = QFrame()  # Use QFrame for card-like styling
                    widget.setStyleSheet(f"""
                        background: {'#FFFFFF' if not self.is_dark_mode else '#4A4A4A'};
                        border-radius: 8px;
                        padding: 10px;
                        box-shadow: 0 2px 4px rgba(0,0,0,0.1);
                    """)
                    layout = QHBoxLayout(widget)
                    layout.setContentsMargins(10, 10, 10, 10)
                    layout.setSpacing(15)

                    label_text = f"Website: {data['website']} | Username: {data['username']}"
                    if category:
                        label_text += f" | Category: {category}"
                    label = QLabel(label_text)
                    label.setFont(QFont("Open Sans", 12))
                    label.setStyleSheet(f"color: {'#333' if not self.is_dark_mode else '#E0E7FF'};")
                    label.setToolTip(label_text)  # Add tooltip for full text
                    layout.addWidget(label, stretch=1)

                    password_label = QLabel("••••••••")
                    password_label.setFont(QFont("Open Sans", 12))
                    password_label.setStyleSheet(f"color: {'#4A90E2' if not self.is_dark_mode else '#fc6a03'};")
                    self.password_labels[data["doc_id"]] = password_label
                    layout.addWidget(password_label)

                    # Show Button with icon and hover effect
                    show_btn = QPushButton("👁️ Show")
                    show_btn.setFont(QFont("Montserrat", 10, QFont.Weight.Bold))
                    show_btn.setStyleSheet("""
                        QPushButton {
                            background: #4A90E2; 
                            color: white; 
                            padding: 5px 10px; 
                            border-radius: 5px;
                            border: none;
                            box-shadow: 0 1px 3px rgba(0,0,0,0.1);
                            transition: transform 0.2s;
                        }
                        QPushButton:hover {
                            background: #357ABD;
                            transform: scale(1.05);
                        }
                    """)
                    show_btn.clicked.connect(lambda checked, d=data, btn=show_btn: self.toggle_password(d, btn))
                    show_btn.setToolTip("Show or hide the password")
                    layout.addWidget(show_btn)

                    # Copy Button with icon and hover effect
                    copy_btn = QPushButton("📋 Copy")
                    copy_btn.setFont(QFont("Montserrat", 10, QFont.Weight.Bold))
                    copy_btn.setStyleSheet("""
                        QPushButton {
                            background: #10B981; 
                            color: white; 
                            padding: 5px 10px; 
                            border-radius: 5px;
                            border: none;
                            box-shadow: 0 1px 3px rgba(0,0,0,0.1);
                            transition: transform 0.2s;
                        }
                        QPushButton:hover {
                            background: #059669;
                            transform: scale(1.05);
                        }
                    """)
                    copy_btn.clicked.connect(lambda checked, d=data: self.copy_password(d))
                    copy_btn.setToolTip("Copy password to clipboard")
                    layout.addWidget(copy_btn)

                    # Edit Button with icon and hover effect
                    edit_btn = QPushButton("✏️ Edit")
                    edit_btn.setFont(QFont("Montserrat", 10, QFont.Weight.Bold))
                    edit_btn.setStyleSheet("""
                        QPushButton {
                            background: #FFD166; 
                            color: #333333; 
                            padding: 5px 10px; 
                            border-radius: 5px;
                            border: none;
                            box-shadow: 0 1px 3px rgba(0,0,0,0.1);
                            transition: transform 0.2s;
                        }
                        QPushButton:hover {
                            background: #FFC107;
                            transform: scale(1.05);
                        }
                    """)
                    edit_btn.clicked.connect(lambda checked, d=data: self.show_edit_credential(d))
                    edit_btn.setToolTip("Edit this credential")
                    layout.addWidget(edit_btn)

                    # Delete Button with icon and hover effect
                    delete_btn = QPushButton("🗑️ Delete")
                    delete_btn.setFont(QFont("Montserrat", 10, QFont.Weight.Bold))
                    delete_btn.setStyleSheet("""
                        QPushButton {
                            background: #FF6B6B; 
                            color: white; 
                            padding: 5px 10px; 
                            border-radius: 5px;
                            border: none;
                            box-shadow: 0 1px 3px rgba(0,0,0,0.1);
                            transition: transform 0.2s;
                        }
                        QPushButton:hover {
                            background: #E55A5A;
                            transform: scale(1.05);
                        }
                    """)
                    delete_btn.clicked.connect(lambda checked, d=data: self.delete_credential(d["doc_id"]))
                    delete_btn.setToolTip("Delete this credential")
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
        if "Show" in button.text():  # Check for "Show" in the text (e.g., "👁️ Show")
            password = decrypt_password(data, self.master_password, self.private_key)
            password_label.setText(password)
            button.setText("👁️ Hide")  # Include the icon when setting to "Hide"
        else:  # If "Hide" is in the text (e.g., "👁️ Hide")
            password_label.setText("••••••••")
            button.setText("👁️ Show")  # Include the icon when setting to "Show"

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
        title.setStyleSheet(f"color: {'#4A90E2' if not self.is_dark_mode else '#fc6a03'};")
        self.content_layout.addWidget(title, alignment=Qt.AlignmentFlag.AlignCenter)

        entries = {}
        for label, key, value, placeholder in [
            ("Website", "website", data["website"], "e.g., example.com"),
            ("Username", "username", data["username"], "e.g., yourname"),
            ("Password", "password", decrypt_password(data, self.master_password, self.private_key),
             "Enter your password"),
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

        # Generate Password Button with icon and hover effect
        generate_btn = QPushButton("🎲 Generate Password")
        generate_btn.setFont(QFont("Montserrat", 12, QFont.Weight.Bold))
        generate_btn.setStyleSheet("""
            QPushButton {
                background: #10B981; 
                color: white; 
                padding: 8px 20px; 
                border-radius: 5px;
                border: none;
                box-shadow: 0 2px 4px rgba(0,0,0,0.15);
                transition: transform 0.2s;
            }
            QPushButton:hover {
                background: #059669;
                transform: scale(1.05);
            }
        """)
        generate_btn.clicked.connect(lambda: [entries["password"].setText(generate_password()), update_strength()])
        generate_btn.setToolTip("Generate a strong random password")
        self.content_layout.addWidget(generate_btn, alignment=Qt.AlignmentFlag.AlignCenter)

        # Save Changes Button with icon and hover effect
        save_btn = QPushButton("💾 Save Changes")
        save_btn.setFont(QFont("Montserrat", 16, QFont.Weight.Bold))
        save_btn.setStyleSheet("""
            QPushButton {
                background: #4A90E2; 
                color: white; 
                padding: 10px 30px; 
                border-radius: 8px;
                border: none;
                box-shadow: 0 2px 4px rgba(0,0,0,0.15);
                transition: transform 0.2s;
            }
            QPushButton:hover {
                background: #357ABD;
                transform: scale(1.05);
            }
        """)
        save_btn.clicked.connect(lambda: self.update_credential(data["doc_id"], entries))
        save_btn.setToolTip("Save the updated credential")
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