# 🛡️ SCAM-SHIELD AI

**SCAM-SHIELD** is a cross-border AI forensic engine designed for real-time phishing mitigation in Southeast Asia. It uses a multi-tiered Artificial Intelligence architecture to detect and block scam messages, malicious URLs, and fraudulent QR codes.

---

## 📥 Installation Guide

Since this is a security-focused prototype that monitors SMS and Notifications, it is not currently available on the Google Play Store. You can download the latest APK from our secure Google Drive link.

### **Step 1: Download the AI Model**
The app requires the Gemma 2B model to perform on-device AI analysis.
1. Download the model: [gemma-2b-it-gpu-int4.bin](https://www.kaggle.com/models/google/gemma/tfLite?select=gemma-2b-it-gpu-int4.bin)
2. Move the downloaded file to: `app/src/main/assets/gemma.bin`

### **Step 2: Download the APK**
👉 **[Download SCAM-SHIELD APK from Google Drive](https://drive.google.com/file/d/1fgxc6KzsCdWJNSrvR5wvpILS33zW5MMA/view?usp=drive_link)**

### **Step 3: Disable Play Protect (Important)**
Because this app requires sensitive permissions (SMS and Notification access) to protect your device, Google Play Protect may flag it as an "Unknown App." 

**To install successfully, you must temporarily disable Play Protect:**
1. Open the **Google Play Store** app.
2. Tap your **Profile Icon** at the top right.
3. Tap **Play Protect** > **Settings** (gear icon).
4. Turn **OFF** "Scan apps with Play Protect."

### **Step 4: Install and Grant Permissions**
1. Open the downloaded `.apk` file.
2. If prompted, allow "Install from Unknown Sources."
3. Open the app and grant the following permissions:
   - **SMS Role**: To filter incoming scam texts.
   - **Notification Access**: To block scams from WhatsApp, Messenger, and Telegram.
   - **Contacts**: To identify trusted senders and detect hacked accounts.

---

## 🚀 Key Features
- **Real-Time SMS Shield**: Instantly quarantines suspicious texts.
- **Notification Guard**: Protects your chat apps (WhatsApp, Messenger, etc.).
- **Smart Contact Analysis**: Detects if a friend's account has been hacked to send scam links.
- **AI Forensic Mentor**: Explains *why* a message was flagged in your native language (Burmese, Thai, etc.).
- **Daily Threat Sync**: Automatically updates its local database with the latest global phishing links.

---

## 🛠️ Technical Stack
- **Language**: Kotlin / Jetpack Compose
- **Local AI**: MediaPipe / Gemma (On-Device LLM)
- **Cloud AI**: Llama 3 (via Ollama/OpenRouter)
- **Intelligence**: VirusTotal API & Phishing.Database
- **Database**: Room (SQLite)

---

## ⚖️ Privacy
SCAM-SHIELD is built with **Privacy-by-Design**. All message analysis is performed locally on your device or via secure local-network AI nodes. Your private messages are never stored on our servers.
