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

# Initialize Firebase
cred = credentials.Certificate("password_manager.json")
initialize_app(cred)
db = firestore.client()
users_ref = db.collection("users")
credentials_ref = db.collection("credentials")


# Encryption/Decryption Functions (unchanged)
def encrypt_with_master_password(data, master_password):
    salt = get_random_bytes(16)
    key = scrypt(master_password.encode(), salt, 32, N=2 ** 14, r=8, p=1)
    cipher = AES.new(key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(data)
    encrypted_data = salt + cipher.nonce + tag + ciphertext
    return base64.b64encode(encrypted_data).decode()


def decrypt_with_master_password(encrypted_data, master_password):
    try:
        data = base64.b64decode(encrypted_data)
        salt, iv, tag, ciphertext = data[:16], data[16:32], data[32:48], data[48:]
        key = scrypt(master_password.encode(), salt, 32, N=2 ** 14, r=8, p=1)
        cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
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


def generate_and_store_keys(user_id, master_password):
    key = RSA.generate(1024)  # Use 4096 in production
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    encrypted_private_key = encrypt_with_master_password(private_key, master_password)
    users_ref.document(user_id).set({
        "public_key": public_key.decode(),
        "encrypted_private_key": encrypted_private_key
    })
    return public_key, private_key


# Password Generator Function
def generate_password(length=16):
    characters = string.ascii_letters + string.digits + string.punctuation
    return ''.join(random.choice(characters) for _ in range(length))


# Password Strength Checker
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
        self.inactivity_timer.setInterval(300000)  # 5 minutes in milliseconds

        # Apply theme
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
            print("Escape pressed, toggling fullscreen")
            if self.isFullScreen():
                self.showNormal()
            else:
                self.showFullScreen()
            print(f"Window state: {'Fullscreen' if self.isFullScreen() else 'Normal'}")
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

    def show_settings(self):
        self.clear_content()
        self.content_layout.setSpacing(20)

        settings_container = QWidget()
        settings_container.setFixedWidth(600)
        settings_container.setFixedHeight(500)
        settings_layout = QVBoxLayout(settings_container)
        settings_layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
        settings_layout.setSpacing(20)

        settings_layout.addSpacing(30)

        title = QLabel("Settings")
        title.setFont(QFont("Montserrat", 48, QFont.Weight.Bold))
        title.setStyleSheet(f"color: {'#4A90E2' if not self.is_dark_mode else '#38b6ff'};")
        settings_layout.addWidget(title, alignment=Qt.AlignmentFlag.AlignCenter)

        account_frame = QFrame()
        account_frame.setStyleSheet(f"""
            background: {'#F9FAFB' if not self.is_dark_mode else '#313131'};
            border-radius: 10px;
            padding-top: 0px;
            padding-right: 0px;
            padding-bottom: 0px;
            padding-left: 0px;
            box-shadow: 0 2px 6px rgba(0,0,0,0.1);
        """)
        account_layout = QHBoxLayout(account_frame)
        account_layout.setSpacing(0)
        account_icon = QLabel("👤")
        account_icon.setFont(QFont("Open Sans", 50))
        account_icon.setStyleSheet(f"color: {'#4A90E2' if not self.is_dark_mode else '#38b6ff'};")
        account_layout.addWidget(account_icon)
        account_label = QLabel(f"{self.user_id}")
        account_label.setFont(QFont("Open Sans", 38, QFont.Weight.Medium))
        account_label.setStyleSheet(f"""
            color: {'#333' if not self.is_dark_mode else '#E0E7FF'};
            padding-top: 0px;
            padding-right: 10px;
            padding-bottom: 0px;
            padding-left: 0px;
        """)
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
        theme_btn.setFixedWidth(300)
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
        logout_btn.setFixedWidth(300)
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
        contact_btn.setFixedWidth(300)
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
        about_btn.setFixedWidth(300)
        about_btn.clicked.connect(self.show_about)
        settings_layout.addWidget(about_btn, alignment=Qt.AlignmentFlag.AlignCenter)

        self.content_layout.addWidget(settings_container, alignment=Qt.AlignmentFlag.AlignCenter)

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
        start_btn.setStyleSheet("background: #4A90E2; color: white; padding: 10px; border-radius: 8px;")
        start_btn.clicked.connect(self.show_add_credential)
        self.content_layout.addWidget(start_btn, alignment=Qt.AlignmentFlag.AlignCenter)

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
            ("Category", "category", "e.g., Work, Personal")  # Changed from "Tag" to "Category"
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

        # Password Strength Indicator
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
        save_btn.setStyleSheet("background: #4A90E2; color: white; padding: 10px; border-radius: 8px;")
        save_btn.clicked.connect(lambda: self.store_credential(entries))
        self.content_layout.addWidget(save_btn, alignment=Qt.AlignmentFlag.AlignCenter)

    def show_view_credentials(self):
        self.clear_content()
        title = QLabel("View Credentials")
        title.setFont(QFont("Montserrat", 30, QFont.Weight.Bold))
        title.setStyleSheet(f"color: {'#4A90E2' if not self.is_dark_mode else '#38b6ff'};")
        self.content_layout.addWidget(title, alignment=Qt.AlignmentFlag.AlignCenter)

        # Search Bar
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

        # Category Filter (changed from Tag Filter)
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
            count = 0
            for doc in docs:
                data = doc.to_dict()
                data["doc_id"] = doc.id
                website = data["website"].lower()
                username = data["username"].lower()
                category = data.get("category", "")
                if (search_text in website or search_text in username) and \
                        (selected_category == "All Categories" or category == selected_category):
                    count += 1
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
                    label.setMinimumHeight(30)
                    layout.addWidget(label)

                    password_label = QLabel("••••••••")
                    password_label.setFont(QFont("Open Sans", 12))
                    password_label.setStyleSheet(f"color: {'#4A90E2' if not self.is_dark_mode else '#38b6ff'};")
                    password_label.setMinimumHeight(30)
                    layout.addWidget(password_label)
                    self.password_labels[data["doc_id"]] = password_label

                    show_btn = QPushButton("Show")
                    show_btn.setFont(QFont("Montserrat", 10))
                    show_btn.setStyleSheet("background: #4A90E2; color: white; padding: 5px; border-radius: 5px;")
                    show_btn.clicked.connect(lambda checked, d=data, btn=show_btn: self.toggle_password(d, btn))
                    layout.addWidget(show_btn)

                    copy_btn = QPushButton("Copy")
                    copy_btn.setFont(QFont("Montserrat", 10))
                    copy_btn.setStyleSheet("background: #10B981; color: white; padding: 5px; border-radius: 5px;")
                    copy_btn.clicked.connect(lambda checked, d=data: self.copy_password(d))
                    layout.addWidget(copy_btn)

                    edit_btn = QPushButton("Edit")
                    edit_btn.setFont(QFont("Montserrat", 10))
                    edit_btn.setStyleSheet("background: #FFD166; color: black; padding: 5px; border-radius: 5px;")
                    edit_btn.clicked.connect(lambda checked, d=data: self.show_edit_credential(d))
                    layout.addWidget(edit_btn)

                    delete_btn = QPushButton("Delete")
                    delete_btn.setFont(QFont("Montserrat", 10))
                    delete_btn.setStyleSheet("background: #FF6B6B; color: white; padding: 5px; border-radius: 5px;")
                    delete_btn.clicked.connect(lambda checked, d=data: self.delete_credential(d["doc_id"]))
                    layout.addWidget(delete_btn)

                    widget.adjustSize()
                    item.setSizeHint(widget.sizeHint().grownBy(QMargins(0, 10, 0, 10)))
                    credential_list.addItem(item)
                    credential_list.setItemWidget(item, widget)
            print(f"Filtered credentials found: {count}")

        search_bar.textChanged.connect(update_credential_list)
        category_filter.currentTextChanged.connect(update_credential_list)
        update_credential_list()

        if credential_list.count() == 0:
            no_creds = QLabel("No credentials found.")
            no_creds.setFont(QFont("Open Sans", 12))
            no_creds.setStyleSheet(f"color: {'#333' if not self.is_dark_mode else '#E0E7FF'};")
            self.content_layout.addWidget(no_creds, alignment=Qt.AlignmentFlag.AlignCenter)

        self.content_layout.addWidget(credential_list, stretch=1)

    def toggle_password(self, data, button):
        password_label = self.password_labels.get(data["doc_id"])
        if not password_label:
            print(f"Error: No password label found for doc_id {data['doc_id']}")
            return
        if button.text() == "Show":
            try:
                password = decrypt_password(data, self.master_password, self.private_key)
                password_label.setText(password)
                button.setText("Hide")
            except Exception as e:
                print(f"Failed to decrypt password: {e}")
        else:
            password_label.setText("••••••••")
            button.setText("Show")

    def copy_password(self, data):
        try:
            password = decrypt_password(data, self.master_password, self.private_key)
            clipboard = QApplication.clipboard()
            clipboard.setText(password)
            print(f"Copied password for {data['website']} to clipboard")
        except Exception as e:
            print(f"Failed to copy password: {e}")

    def delete_credential(self, doc_id):
        credentials_ref.document(doc_id).delete()
        print(f"Deleted credential with Doc ID: {doc_id}")
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
            ("Password", "password", decrypt_password(data, self.master_password, self.private_key),
             "Enter your password"),
            ("Category", "category", data.get("category", ""), "e.g., Work, Personal")
            # Changed from "Tag" to "Category"
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

        # Password Strength Indicator
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
        update_strength()  # Initial check

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
        save_btn.setStyleSheet("background: #4A90E2; color: white; padding: 10px; border-radius: 8px;")
        save_btn.clicked.connect(lambda: self.update_credential(data["doc_id"], entries))
        self.content_layout.addWidget(save_btn, alignment=Qt.AlignmentFlag.AlignCenter)

    def login(self):
        try:
            user_id = self.entries["username"].text()
            master_password = self.entries["password"].text()
            doc = users_ref.document(user_id).get()
            print(f"Logging in user: {user_id}")
            if doc.exists:
                encrypted_private_key = doc.to_dict()["encrypted_private_key"]
                self.public_key = doc.to_dict()["public_key"]
                print(f"Retrieved encrypted private key: {encrypted_private_key[:20]}...")
                self.private_key = decrypt_with_master_password(encrypted_private_key, master_password)
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
                self.public_key, self.private_key = generate_and_store_keys(user_id, master_password)
                self.user_id = user_id
                self.master_password = master_password
                print(f"New user created: {user_id}")
                for btn in self.sidebar_buttons.values():
                    btn.setEnabled(True)
                self.reset_inactivity_timer()
                self.show_welcome_guide()
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

    def store_credential(self, entries):
        category = entries["category"].text()
        print(f"Storing credential with category: '{category}'")  # Debug
        encrypted_data = encrypt_password(entries["password"].text(), self.master_password, self.public_key)
        doc_ref = credentials_ref.add({
            "user_id": self.user_id,
            "website": entries["website"].text(),
            "username": entries["username"].text(),
            "category": category,  # Changed from "tag" to "category"
            **encrypted_data
        })
        print(
            f"Credential saved for {self.user_id}: {entries['website']} (Doc ID: {doc_ref[1].id}, Category: '{category}')")
        self.show_view_credentials()

    def update_credential(self, doc_id, entries):
        category = entries["category"].text()
        print(f"Updating credential with category: '{category}'")  # Debug
        encrypted_data = encrypt_password(entries["password"].text(), self.master_password, self.public_key)
        credentials_ref.document(doc_id).update({
            "website": entries["website"].text(),
            "username": entries["username"].text(),
            "category": category,  # Changed from "tag" to "category"
            **encrypted_data
        })
        print(f"Credential updated: {entries['website']} (Doc ID: {doc_id}, Category: '{category}')")
        self.show_view_credentials()


if __name__ == "__main__":
    app = QApplication(sys.argv)
    app.setStyle("Fusion")
    palette = QPalette()
    palette.setColor(QPalette.ColorRole.Window, QColor("#F5F6F5"))
    app.setPalette(palette)
    window = PasswordManagerWindow()
    sys.exit(app.exec())