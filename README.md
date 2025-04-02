
<h1 align="center">
 <img src="https://github.com/user-attachments/assets/49923bf9-9c42-4f2b-a67f-2d4ce476899f" alt="Version"/>


</h1>
<p align="center"><em>Your Fortress for Passwords – Secure, Simple, Savage.</em></p>

<p align="center">
  <img src="https://img.shields.io/badge/Version-1.0-blue?style=for-the-badge" alt="Version"/>
  <img src="https://img.shields.io/badge/License-MIT-orange?style=for-the-badge" alt="License"/>
  <img src="https://img.shields.io/badge/Python-3.9+-green?style=for-the-badge" alt="Python"/>
  <img src="https://img.shields.io/badge/Status-Awesome-ff69b4?style=for-the-badge" alt="Status"/>
</p>

---

## 🌟 What’s PassGuard?

PassGuard is your go-to **password manager** that locks your logins tight with **AES** and **RSA** encryption—the same stuff Google and WhatsApp swear by. Sick of weak passwords or forgetting your Netflix login? PassGuard’s got you with a sleek UI, random password generation, and recovery options like Face Scan or Trusted Contact. It’s secure, it’s smooth, and it’s built for *everyone*—from busy pros to your grandma.

### ✨ Features
- **Add & Store**: Save website creds with categories (Work, Fun, Whatever).  
- **Generate**: Random, uncrackable passwords (e.g., `Kj#9mPx!vL2&8nQ`).  
- **Check Strength**: Real-time password strength meter—Weak, Medium, or Strong, your call.  
- **Recover**: Forgot your master password? Face Scan, Device Fingerprint, or a buddy’s got your back.  
- **View**: Searchable list—show, copy, edit, or delete with a click.  
- **Themes**: Blue vibes in light mode, orange fire in dark mode.  

---

## 🛠️ Setup – Get It Running

### Prerequisites
- Python 3.9+ 🐍  
- Firebase account (for the backend vault) 🔥  
- Webcam (optional, for Face Scan recovery) 📸  

### Installation
1. **Clone the Repo**  
   ```bash
   git clone https://github.com/iapoorv01/PassGuard.git
   cd PassGuard
   ```

2. **Install Dependencies**  
   ```bash
   pip install -r requirements.txt
   ```
   *(Includes PyQt6, firebase-admin, pycryptodome, face_recognition, etc.)*

3. **Set Up Firebase**  
   - Grab your `password_manager.json` from Firebase Console.  
   - Drop it in the root folder.  

4. **Run It**  
   ```bash
   python PassGuard.py
   ```
   Boom—log in, lock it down, and vibe.

---

## 🔐 Encryption – How It’s Locked Tight

PassGuard uses **AES** and **RSA** to make your passwords hacker-proof:  
- **AES**: Scrambles your passwords with a key derived from your master password. Unreadable gibberish to anyone else.  
- **RSA**: Locks that AES key with math so hardcore, it’s used by WhatsApp and Google. Double-layered fortress vibes.  

```python
# Sneak peek at the magic
encrypted = encrypt_password("mysecret", master_password, public_key)
decrypted = decrypt_password(encrypted, master_password, private_key)
```

---

## 🎨 Screenshots

| Light Mode  Dark Mode |

| ![image](https://github.com/user-attachments/assets/be34da38-0d81-4c63-afa6-eee94be6ff2c)
   


---

## 🚀 Why PassGuard?

- **Relatable**: For the “I forgot my password again” crew.  
- **Secure**: AES + RSA = no hacks, just facts.  
- **Simple**: Clean flow—add, view, recover, done.  
- **You**: Built by Apoorv Gupta, a dev who gets it.

---

## 🤝 Contributing

Got ideas? Fork it, tweak it, PR it!  
- Bug fixes? Yes, please.  
- New features? Let’s vibe—open an issue first.  

---

## 📜 License

MIT—do your thing, just give a shoutout.  

<p align="center">
  <em>Made with 💪 by Apoorv Gupta, 2025</em>
</p>

<p align="center">
  <a href="https://www.linkedin.com/in/-apoorv-/">Say hi on LinkedIn!</a>
</p>


---
