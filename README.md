🛡️ Ransomware Training Simulator – KORRAGG CTF

This repository contains KORRAGG Security System v2.4.7, a ransomware simulation project designed strictly for cybersecurity training, awareness, and Capture the Flag (CTF) exercises.

The simulator encrypts files in a controlled environment, generates a ransom note, and provides a decryption challenge. It allows students and professionals to practice reverse engineering, incident response, and forensic investigation without real-world risk.

⚠️ Disclaimer:
This project is for educational and research purposes only. Use only in virtual machines or isolated labs. The authors bear no responsibility for any misuse.

✨ Features

🔐 File Encryption (AES-256) with reversible recovery.

📄 Ransom Note Generation (.hta styled with warnings & payment request).

🖥️ GUI Interface with timer, attempts, and attacker profile.

🔑 Decryption Challenge (requires analyzing the source to find the correct key).

🎭 Gamified CTF Experience with hints, fake payment checks, and achievements.

🧾 Forensic Artifacts (logs, encrypted .NCRIC files, ransom notes).

📂 Files

ransarnav.py → Main ransomware simulator with GUI.

decryptor2.exe → Standalone decryptor utility.

korragg.png → (Optional) Attacker profile image used in GUI.

🚀 Setup & Usage
Requirements

Python 3.x

pycryptodome, Pillow, tkinter

Install dependencies:

pip install pycryptodome pillow

Run Simulator
remove comment (""") from ranskorragg.py manually
python ranskorragg.py

Decrypt Files

Either enter the correct key in the simulator GUI or use:

decryptor2.exe

🎯 Purpose

Train students in cyber defense & incident response.

Provide a CTF-style challenge for reverse engineering.

Generate forensic artifacts for investigation exercises.

Raise awareness on ransomware tactics in a safe environment.
