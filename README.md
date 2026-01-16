# 🕵️‍♂️ Web-Based Digital Forensic Toolkit (W-DFT)

A full-stack forensic investigation platform built with **Flask** and **Tailwind CSS**. It allows investigators to manage cases, analyze files, and perform real-time network sniffing via a modern web interface.

## 📸 Screenshots
*(See the /screenshots folder for more)*

## 🚀 Features
* **Case Management:** Create cases and save evidence logs to a local SQLite database.
* **Live Sniffer:** Real-time packet capture streamed via **WebSockets (Socket.IO)**.
* **File Forensics:** Hash calculation, Metadata extraction (PDF/DOCX), and EXIF analysis.
* **System Analysis:** Windows Registry (USB History) and Browser History parsing.
* **Crypto Tools:** XOR, ROT13, and Base64 decoders for de-obfuscation.

## 🛠️ Installation

1. **Clone the repo**
   ```bash
   git clone [https://github.com/Sreeniketh/Digital-Forensic-Toolkit.git](https://github.com/Sreeniketh/Digital-Forensic-Toolkit.git)
   cd Digital-Forensic-Toolkit