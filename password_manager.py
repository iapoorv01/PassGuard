import sys
from PyQt6.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
                             QPushButton, QLineEdit, QLabel, QFrame, QGraphicsScene, QGraphicsView, QListWidget,
                             QListWidgetItem)
from PyQt6.QtCore import Qt, QTimer, QRectF, QPointF, QEvent, QMargins
from PyQt6.QtGui import QPalette, QColor, QFont, QBrush, QPen
import random
from firebase_admin import credentials, firestore, initialize_app
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Protocol.KDF import scrypt
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
import base64

# Initialize Firebase
cred = credentials.Certificate("password_manager.json")
initialize_app(cred)
db = firestore.client()
users_ref = db.collection("users")
credentials_ref = db.collection("credentials")

# Encryption/Decryption Functions
def encrypt_with_master_password(data, master_password):
    salt = get_random_bytes(16)
    key = scrypt(master_password.encode(), salt, 32, N=2**14, r=8, p=1)
    cipher = AES.new(key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(data)
    encrypted_data = salt + cipher.nonce + tag + ciphertext
    return base64.b64encode(encrypted_data).decode()


def decrypt_with_master_password(encrypted_data, master_password):
    try:
        data = base64.b64decode(encrypted_data)
        salt = data[:16]
        iv = data[16:32]  # 16 bytes for IV, matching your decrypt_private_key
        tag = data[32:48]
        ciphertext = data[48:]
        key = scrypt(master_password.encode(), salt, 32, N=2 ** 14, r=8, p=1)
        cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
        decrypted_data = cipher.decrypt_and_verify(ciphertext, tag)
        print("Private key decrypted successfully")
        return decrypted_data
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

def generate_and_store_keys(user_id, master_password):
    key = RSA.generate(1024)  # Testing; use 4096 for production
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    encrypted_private_key = encrypt_with_master_password(private_key, master_password)
    users_ref.document(user_id).set({
        "public_key": public_key.decode(),
        "encrypted_private_key": encrypted_private_key
    })
    print(f"Generated and stored keys for {user_id}: {encrypted_private_key[:20]}... (encrypted)")
    return public_key, private_key

# Main Window
class PasswordManagerWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Secure Password Manager")
        self.setGeometry(100, 100, 1000, 700)
        self.setStyleSheet("background: qlineargradient(x1:0, y1:0, x2:1, y2:1, stop:0 #E0E7FF, stop:1 #FFFFFF);")
        self.showFullScreen()

        central_widget = QWidget(self)
        self.setCentralWidget(central_widget)
        main_layout = QHBoxLayout(central_widget)
        main_layout.setContentsMargins(0, 0, 0, 0)

        self.scene = QGraphicsScene()
        self.view = QGraphicsView(self.scene, self)
        self.view.setStyleSheet("background: transparent; border: none;")
        self.view.setGeometry(0, 0, self.width(), self.height())
        self.glitter_particles = []
        self.timer = QTimer()
        self.timer.timeout.connect(self.update_glitter)
        self.timer.start(50)

        sidebar = QFrame()
        sidebar.setFixedWidth(250)
        sidebar.setStyleSheet("background: #4A90E2; border-radius: 10px;")
        sidebar_layout = QVBoxLayout(sidebar)
        sidebar_layout.setContentsMargins(10, 20, 10, 20)
        logo = QLabel("🔒 PassGuard")
        logo.setFont(QFont("Montserrat", 20, QFont.Weight.Bold))
        logo.setStyleSheet("color: white;")
        sidebar_layout.addWidget(logo, alignment=Qt.AlignmentFlag.AlignCenter)
        for text, cmd in [("Add Credential", self.show_add_credential),
                          ("View Credentials", self.show_view_credentials), ("Settings", lambda: print("Settings"))]:
            btn = QPushButton(text)
            btn.setFont(QFont("Montserrat", 14))
            btn.setStyleSheet("""
                QPushButton { background: transparent; color: white; padding: 10px; border-radius: 5px; }
                QPushButton:hover { background: rgba(255, 255, 255, 0.2); }
            """)
            btn.clicked.connect(cmd)
            sidebar_layout.addWidget(btn)
        sidebar_layout.addStretch()

        self.content = QFrame()
        self.content.setStyleSheet(
            "background: rgba(255, 255, 255, 0.9); border-radius: 10px; box-shadow: 0 4px 12px rgba(0,0,0,0.1);")
        self.content_layout = QVBoxLayout(self.content)
        self.password_labels = {}  # Initialize here, not in loop
        self.show_login()

        main_layout.addWidget(sidebar)
        main_layout.addWidget(self.content, stretch=1)
        self.installEventFilter(self)

    def eventFilter(self, obj, event):
        if event.type() == QEvent.Type.KeyPress and event.key() == Qt.Key.Key_Escape:
            if self.isFullScreen():
                self.showNormal()
            else:
                self.showFullScreen()
            self.view.setGeometry(0, 0, self.width(), self.height())
            return True
        return super().eventFilter(obj, event)

    def update_glitter(self):
        if len(self.glitter_particles) < 50 and random.random() < 0.3:
            x = random.randint(0, self.width())
            y = random.randint(0, self.height())
            size = random.randint(3, 8)
            particle = self.scene.addEllipse(x, y, size, size, QPen(Qt.PenStyle.NoPen), QBrush(QColor("#38b6ff")))
            self.glitter_particles.append(
                {"item": particle, "vx": random.uniform(-1, 1), "vy": random.uniform(-1, 1), "life": 100})
        for particle in self.glitter_particles[:]:
            rect = particle["item"].rect()
            rect.translate(particle["vx"], particle["vy"])
            particle["item"].setRect(rect)
            particle["life"] -= 1
            if particle["life"] <= 0 or rect.x() < 0 or rect.x() > self.width() or rect.y() < 0 or rect.y() > self.height():
                self.scene.removeItem(particle["item"])
                self.glitter_particles.remove(particle)

    def clear_content(self):
        for widget in self.content.findChildren(QWidget):
            widget.deleteLater()

    def show_login(self):
        self.clear_content()
        title = QLabel("Welcome Back")
        title.setFont(QFont("Montserrat", 30, QFont.Weight.Bold))
        title.setStyleSheet("color: #4A90E2;")
        self.content_layout.addWidget(title, alignment=Qt.AlignmentFlag.AlignCenter)

        self.entries = {}
        for label, key, echo in [("Username", "username", QLineEdit.EchoMode.Normal),
                                 ("Master Password", "password", QLineEdit.EchoMode.Password)]:
            self.content_layout.addWidget(QLabel(label, font=QFont("Open Sans", 12)))
            entry = QLineEdit()
            entry.setFont(QFont("Open Sans", 14))
            entry.setStyleSheet("background: #E0E7FF; border: none; padding: 8px; border-radius: 5px;")
            entry.setEchoMode(echo)
            self.content_layout.addWidget(entry)
            self.entries[key] = entry

        login_btn = QPushButton("Login")
        login_btn.setFont(QFont("Montserrat", 16, QFont.Weight.Bold))
        login_btn.setStyleSheet("background: #4A90E2; color: white; padding: 10px; border-radius: 8px;")
        login_btn.clicked.connect(self.login)
        self.content_layout.addWidget(login_btn, alignment=Qt.AlignmentFlag.AlignCenter)
        self.content_layout.addStretch()

    def show_add_credential(self):
        self.clear_content()
        title = QLabel("Add Credential")
        title.setFont(QFont("Montserrat", 30, QFont.Weight.Bold))
        title.setStyleSheet("color: #4A90E2;")
        self.content_layout.addWidget(title, alignment=Qt.AlignmentFlag.AlignCenter)

        entries = {}
        for label, key in [("Website", "website"), ("Username", "username"), ("Password", "password")]:
            self.content_layout.addWidget(QLabel(label, font=QFont("Open Sans", 12)))
            entry = QLineEdit()
            entry.setFont(QFont("Open Sans", 14))
            entry.setStyleSheet("background: #E0E7FF; border: none; padding: 8px; border-radius: 5px;")
            if key == "password":
                entry.setEchoMode(QLineEdit.EchoMode.Password)
            self.content_layout.addWidget(entry)
            entries[key] = entry

        save_btn = QPushButton("Save")
        save_btn.setFont(QFont("Montserrat", 16, QFont.Weight.Bold))
        save_btn.setStyleSheet("background: #4A90E2; color: white; padding: 10px; border-radius: 8px;")
        save_btn.clicked.connect(lambda: self.store_credential(entries))
        self.content_layout.addWidget(save_btn, alignment=Qt.AlignmentFlag.AlignCenter)
        self.content_layout.addStretch()

    def show_view_credentials(self):
        self.clear_content()
        title = QLabel("View Credentials")
        title.setFont(QFont("Montserrat", 30, QFont.Weight.Bold))
        title.setStyleSheet("color: #4A90E2;")
        self.content_layout.addWidget(title, alignment=Qt.AlignmentFlag.AlignCenter)

        credential_list = QListWidget()
        credential_list.setFont(QFont("Open Sans", 12))
        credential_list.setStyleSheet("background: #E0E7FF; border: none; padding: 10px; border-radius: 5px;")
        credential_list.setSpacing(5)  # Space between items
        credential_list.setMinimumWidth(600)  # Optional: Ensure width is reasonable

        docs = credentials_ref.where("user_id", "==", self.user_id).stream()
        print(f"Fetching credentials for user_id: {self.user_id}")
        count = 0
        for doc in docs:
            count += 1
            data = doc.to_dict()
            data["doc_id"] = doc.id
            print(f"Found credential: {data['website']}, {data['username']}")

            item = QListWidgetItem()
            widget = QWidget()
            layout = QHBoxLayout(widget)
            layout.setContentsMargins(5, 5, 5, 5)

            label = QLabel(f"Website: {data['website']} | Username: {data['username']}")
            label.setFont(QFont("Open Sans", 12))
            label.setMinimumHeight(30)  # Force height to fit text
            layout.addWidget(label)

            password_label = QLabel("••••••••")
            password_label.setFont(QFont("Open Sans", 12))
            password_label.setStyleSheet("color: #4A90E2;")
            password_label.setMinimumHeight(30)  # Match label height
            layout.addWidget(password_label)
            self.password_labels[data["doc_id"]] = password_label

            show_btn = QPushButton("Show")
            show_btn.setFont(QFont("Montserrat", 10))
            show_btn.setStyleSheet("background: #4A90E2; color: white; padding: 5px; border-radius: 5px;")
            show_btn.clicked.connect(lambda checked, d=data, btn=show_btn: self.toggle_password(d, btn))
            layout.addWidget(show_btn)

            edit_btn = QPushButton("Edit")
            edit_btn.setFont(QFont("Montserrat", 10))
            edit_btn.setStyleSheet("background: #FFD166; color: black; padding: 5px; border-radius: 5px;")
            edit_btn.clicked.connect(lambda checked, d=data: self.show_edit_credential(d))
            layout.addWidget(edit_btn)

            widget.adjustSize()
            item.setSizeHint(widget.sizeHint().grownBy(QMargins(0, 10, 0, 10)))  # Use QMargins directly
            credential_list.addItem(item)
            credential_list.setItemWidget(item, widget)

        print(f"Total credentials found: {count}")
        if count == 0:
            self.content_layout.addWidget(QLabel("No credentials found."), alignment=Qt.AlignmentFlag.AlignCenter)

        self.content_layout.addWidget(credential_list, stretch=1)  # Stretch to fill space
        self.content_layout.addStretch()

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

    def show_edit_credential(self, data):
        self.clear_content()
        title = QLabel("Edit Credential")
        title.setFont(QFont("Montserrat", 30, QFont.Weight.Bold))
        title.setStyleSheet("color: #4A90E2;")
        self.content_layout.addWidget(title, alignment=Qt.AlignmentFlag.AlignCenter)

        entries = {}
        for label, key, value in [("Website", "website", data["website"]),
                                  ("Username", "username", data["username"]),
                                  ("Password", "password", decrypt_password(data, self.master_password, self.private_key))]:
            self.content_layout.addWidget(QLabel(label, font=QFont("Open Sans", 12)))
            entry = QLineEdit()
            entry.setFont(QFont("Open Sans", 14))
            entry.setStyleSheet("background: #E0E7FF; border: none; padding: 8px; border-radius: 5px;")
            entry.setText(value)
            if key == "password":
                entry.setEchoMode(QLineEdit.EchoMode.Password)
            self.content_layout.addWidget(entry)
            entries[key] = entry

        save_btn = QPushButton("Save Changes")
        save_btn.setFont(QFont("Montserrat", 16, QFont.Weight.Bold))
        save_btn.setStyleSheet("background: #4A90E2; color: white; padding: 10px; border-radius: 8px;")
        save_btn.clicked.connect(lambda: self.update_credential(data["doc_id"], entries))
        self.content_layout.addWidget(save_btn, alignment=Qt.AlignmentFlag.AlignCenter)
        self.content_layout.addStretch()

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
                self.show_view_credentials()
            else:
                self.public_key, self.private_key = generate_and_store_keys(user_id, master_password)
                self.user_id = user_id
                self.master_password = master_password
                print(f"New user created: {user_id}")
                self.show_add_credential()
        except Exception as e:
            error_label = QLabel(f"Login failed: {str(e)}")
            error_label.setFont(QFont("Open Sans", 12))
            error_label.setStyleSheet("color: red;")
            self.content_layout.addWidget(error_label, alignment=Qt.AlignmentFlag.AlignCenter)

    def store_credential(self, entries):
        encrypted_data = encrypt_password(entries["password"].text(), self.master_password, self.public_key)
        doc_ref = credentials_ref.add({
            "user_id": self.user_id,
            "website": entries["website"].text(),
            "username": entries["username"].text(),
            **encrypted_data
        })
        print(f"Credential saved for {self.user_id}: {entries['website']} (Doc ID: {doc_ref[1].id})")
        self.show_view_credentials()

    def update_credential(self, doc_id, entries):
        encrypted_data = encrypt_password(entries["password"].text(), self.master_password, self.public_key)
        credentials_ref.document(doc_id).update({
            "website": entries["website"].text(),
            "username": entries["username"].text(),
            **encrypted_data
        })
        print(f"Credential updated: {entries['website']} (Doc ID: {doc_id})")
        self.show_view_credentials()

if __name__ == "__main__":
    app = QApplication(sys.argv)
    app.setStyle("Fusion")
    palette = QPalette()
    palette.setColor(QPalette.ColorRole.Window, QColor("#F5F6F5"))
    app.setPalette(palette)
    window = PasswordManagerWindow()
    sys.exit(app.exec())