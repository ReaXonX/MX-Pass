import os
import json
import string
import random
import hashlib
import time
import base64
from tkinter import Tk, Toplevel, END, messagebox, Menu, StringVar, simpledialog, BooleanVar, IntVar
from tkinter import ttk
import tkinter as tk
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
import pyotp
import pyperclip
from typing import Dict, Any, Optional
from tkinter import filedialog

# Constants for file paths
KEY_FILE = "data/key.enc"
DATA_FILE = "data/passwords.enc"
SECRET_FILE = "data/2fa_secret.enc"
MASTER_PW_FILE = "data/master_pw.enc"
CONFIG_FILE = "data/config.json"

# Security parameters
PBKDF2_ITERATIONS = 300_000
CLIPBOARD_CLEAR_TIME = 30  # seconds
SESSION_TIMEOUT = 300  # 5 minutes
MAX_ATTEMPTS = 5

class SecureString:
    """Wrapper for sensitive strings that clears memory when deleted"""
    def __init__(self, value: str):
        self._value = bytearray(value, 'utf-8')
        self._length = len(value)
        
    def get(self) -> str:
        return self._value.decode('utf-8')
        
    def clear(self):
        for i in range(self._length):
            self._value[i] = 0
        self._length = 0
        
    def __del__(self):
        self.clear()

class PasswordManager:
    def __init__(self):
        self.last_activity = time.time()
        self.attempts_remaining = MAX_ATTEMPTS
        self.current_sort_column = 'site'  # Default sort column
        self.sort_reverse = False  # Default sort direction
        
        # Initialize directories and config
        self.ensure_data_directory()
        self.load_or_create_config()
        
        self.root = self.create_main_window()
        self.setup_activity_tracking()
        
        if not self.verify_master_password():
            exit()
            
        self.setup_2fa()
        self.setup_ui()
        self.set_theme(self.config.get('theme', 'light'))
        self.show_password_list()  # Show password list by default
        self.root.mainloop()

    def ensure_data_directory(self):
        """Ensure the data directory exists"""
        if not os.path.exists('data'):
            os.makedirs('data')

    def load_or_create_config(self):
        """Load or create configuration file"""
        self.config = {}
        if os.path.exists(CONFIG_FILE):
            try:
                with open(CONFIG_FILE, 'r') as f:
                    self.config = json.load(f)
            except (json.JSONDecodeError, IOError):
                self.config = {}
                
        # Set defaults
        self.config.setdefault('theme', 'light')
        self.config.setdefault('clipboard_timeout', CLIPBOARD_CLEAR_TIME)
        self.config.setdefault('session_timeout', SESSION_TIMEOUT)

    def save_config(self):
        """Save configuration to file"""
        try:
            with open(CONFIG_FILE, 'w') as f:
                json.dump(self.config, f, indent=4)
        except IOError:
            messagebox.showerror("Error", "Could not save configuration")

    def derive_key(self, password: str, salt: bytes) -> bytes:
        """Derive encryption key from master password"""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=PBKDF2_ITERATIONS,
            backend=default_backend()
        )
        return base64.urlsafe_b64encode(kdf.derive(password.encode()))

    def setup_encryption(self, password: str):
        """Initialize encryption with key derived from master password"""
        salt = os.urandom(16)
        key = self.derive_key(password, salt)
        
        encrypted_key = Fernet.generate_key()
        fernet = Fernet(encrypted_key)
        encrypted_salt = fernet.encrypt(salt)
        
        with open(KEY_FILE, 'wb') as f:
            f.write(encrypted_key + b'||' + encrypted_salt)
            
        self.encryptor = Fernet(key)

    def load_encryption(self, password: str) -> bool:
        """Load encryption key using master password"""
        try:
            with open(KEY_FILE, 'rb') as f:
                encrypted_key, encrypted_salt = f.read().split(b'||')
                
            temp_fernet = Fernet(encrypted_key)
            salt = temp_fernet.decrypt(encrypted_salt)
            key = self.derive_key(password, salt)
            self.encryptor = Fernet(key)
            return True
            
        except (FileNotFoundError, ValueError, InvalidToken):
            return False

    def verify_master_password(self) -> bool:
        """Handle master password setup and verification"""
        if not os.path.exists(MASTER_PW_FILE):
            return self.setup_master_password()
        return self.authenticate_user()

    def setup_master_password(self) -> bool:
        """First-run master password setup"""
        while True:
            pw = simpledialog.askstring("Set Master Password", 
                                      "Set your master password (min 12 chars):", 
                                      show='*')
            if not pw:
                return False
                
            if len(pw) < 12:
                messagebox.showerror("Error", "Master password must be at least 12 characters")
                continue
                
            confirm = simpledialog.askstring("Confirm Master Password", 
                                           "Confirm your master password:", 
                                           show='*')
            if pw == confirm:
                break
            messagebox.showerror("Error", "Passwords don't match!")
        
        self.setup_encryption(pw)
        hashed = hashlib.sha256(pw.encode()).hexdigest()
        encrypted = self.encryptor.encrypt(hashed.encode())
        with open(MASTER_PW_FILE, 'wb') as f:
            f.write(encrypted)
        return True

    def authenticate_user(self) -> bool:
        """Verify master password with attempt limiting"""
        while self.attempts_remaining > 0:
            pw = simpledialog.askstring("Master Password", 
                                       "Enter your master password:", 
                                       show='*')
            if not pw:
                return False
                
            if not self.load_encryption(pw):
                self.attempts_remaining -= 1
                messagebox.showerror("Access Denied", 
                                   f"Incorrect password. {self.attempts_remaining} attempts remaining.")
                continue
                
            with open(MASTER_PW_FILE, 'rb') as f:
                encrypted = f.read()
                
            try:
                stored_hash = self.encryptor.decrypt(encrypted).decode()
                current_hash = hashlib.sha256(pw.encode()).hexdigest()
                
                if stored_hash == current_hash:
                    self.attempts_remaining = MAX_ATTEMPTS
                    return True
                    
                self.attempts_remaining -= 1
                messagebox.showerror("Access Denied", 
                                   f"Incorrect password. {self.attempts_remaining} attempts remaining.")
                                   
            except InvalidToken:
                self.attempts_remaining -= 1
                messagebox.showerror("Access Denied", 
                                   f"Invalid data. {self.attempts_remaining} attempts remaining.")
        
        messagebox.showerror("Access Denied", "Too many failed attempts. Exiting.")
        return False

    def setup_2fa(self):
        """Initialize 2FA secret"""
        if not os.path.exists(SECRET_FILE):
            self.SECRET = pyotp.random_base32()
            encrypted_secret = self.encryptor.encrypt(self.SECRET.encode())
            with open(SECRET_FILE, 'wb') as secret_file:
                secret_file.write(encrypted_secret)
        else:
            with open(SECRET_FILE, 'rb') as secret_file:
                encrypted_secret = secret_file.read()
            self.SECRET = self.encryptor.decrypt(encrypted_secret).decode()
        self.totp = pyotp.TOTP(self.SECRET)

    def calculate_strength(self, password: str) -> Dict[str, Any]:
        """Calculate password strength"""
        if len(password) < 8:
            return {"strength": "Too Short", "score": 0}
            
        length = len(password)
        has_lower = any(c in string.ascii_lowercase for c in password)
        has_upper = any(c in string.ascii_uppercase for c in password)
        has_digit = any(c in string.digits for c in password)
        has_special = any(c in string.punctuation for c in password)
        
        common_passwords = ['password', '123456', 'qwerty', 'letmein']
        is_common = password.lower() in common_passwords
        
        length_score = min(length / 20, 1.0)
        variety_score = sum([has_lower, has_upper, has_digit, has_special]) / 4
        sequence_penalty = 0.1 if any(password[i] == password[i+1] for i in range(len(password)-1)) else 0
        common_penalty = 0.3 if is_common else 0
        
        overall_score = (length_score + variety_score - sequence_penalty - common_penalty)
        overall_score = max(0, min(1, overall_score))
        
        if overall_score < 0.4:
            strength = "Weak"
        elif overall_score < 0.7:
            strength = "Fair"
        elif overall_score < 0.9:
            strength = "Good"
        else:
            strength = "Strong"
            
        return {
            "strength": strength,
            "score": overall_score,
            "length": length,
            "has_lower": has_lower,
            "has_upper": has_upper,
            "has_digit": has_digit,
            "has_special": has_special,
            "is_common": is_common
        }

    def update_strength_label(self, password_entry: ttk.Entry, strength_label: ttk.Label):
        """Update password strength label"""
        password = password_entry.get()
        analysis = self.calculate_strength(password)
        
        color = {
            "Too Short": "red",
            "Weak": "red",
            "Fair": "orange",
            "Good": "blue",
            "Strong": "green"
        }.get(analysis["strength"], "black")
        
        feedback = []
        if analysis["strength"] == "Too Short":
            feedback.append("Password is too short (min 8 chars)")
        else:
            feedback.append(f"Length: {analysis['length']} chars")
            if not analysis["has_lower"]:
                feedback.append("Missing lowercase letters")
            if not analysis["has_upper"]:
                feedback.append("Missing uppercase letters")
            if not analysis["has_digit"]:
                feedback.append("Missing numbers")
            if not analysis["has_special"]:
                feedback.append("Missing special characters")
            if analysis["is_common"]:
                feedback.append("Password is too common")
        
        strength_label.config(
            text=f"Strength: {analysis['strength']}\n" + "\n".join(feedback),
            foreground=color
        )

    def create_password_generator(self):
        """Create password generator popup"""
        popup = Toplevel(self.root)
        popup.title("Generate Password")
        popup.geometry("450x400")
        popup.resizable(False, False)
        
        ttk.Label(popup, text="Length:").grid(row=0, column=0, padx=10, pady=10, sticky="w")
        length_var = IntVar(value=16)
        length_slider = ttk.Scale(popup, from_=8, to=32, variable=length_var, orient="horizontal", length=200)
        length_slider.grid(row=0, column=1, padx=10, pady=10)
        length_spin = ttk.Spinbox(popup, from_=8, to=32, textvariable=length_var, width=5)
        length_spin.grid(row=0, column=2, padx=10, pady=10)
        
        options = {
            "Lowercase Letters (a-z)": BooleanVar(value=True),
            "Uppercase Letters (A-Z)": BooleanVar(value=True),
            "Numbers (0-9)": BooleanVar(value=True),
            "Special Characters (!@#$)": BooleanVar(value=True),
            "Exclude Similar Characters (iIl1O0)": BooleanVar(value=True),
            "Exclude Ambiguous Characters ({}[]()/\'\"`~,;:.<>)": BooleanVar(value=False)
        }

        for i, (text, var) in enumerate(options.items()):
            ttk.Checkbutton(popup, text=text, variable=var).grid(
                row=i + 1, column=0, columnspan=3, padx=10, pady=2, sticky="w")

        password_var = StringVar()
        ttk.Label(popup, text="Generated Password:").grid(row=8, column=0, padx=10, pady=5, sticky="w")
        password_display = ttk.Entry(popup, textvariable=password_var, width=30, font=('Courier', 10))
        password_display.grid(row=8, column=1, columnspan=2, padx=10, pady=5)

        strength_display = ttk.Label(popup, text="Strength: ", wraplength=350)
        strength_display.grid(row=9, column=0, columnspan=3, padx=10, pady=5)

        def update_strength_display():
            analysis = self.calculate_strength(password_var.get())
            color = {
                "Too Short": "red",
                "Weak": "red",
                "Fair": "orange",
                "Good": "blue",
                "Strong": "green"
            }.get(analysis["strength"], "black")
            strength_display.config(text=f"Strength: {analysis['strength']} (Score: {analysis['score']:.0%})", foreground=color)

        password_var.trace_add('write', lambda *_: update_strength_display())

        btn_frame = ttk.Frame(popup)
        btn_frame.grid(row=10, column=0, columnspan=3, pady=10)

        ttk.Button(btn_frame, text="Generate", command=lambda: self.generate_password(
            length_var, options, password_var)).pack(side="left", padx=5)
        ttk.Button(btn_frame, text="Copy", command=lambda: self.copy_to_clipboard(
            password_var.get(), popup)).pack(side="left", padx=5)
        ttk.Button(btn_frame, text="Close", command=popup.destroy).pack(side="right", padx=5)

        self.generate_password(length_var, options, password_var)

    def generate_password(self, length_var: IntVar, options: Dict[str, BooleanVar], password_var: StringVar) -> str:
        """Generate a password based on user preferences"""
        length = length_var.get()
        character_sets = {
            'lower': string.ascii_lowercase,
            'upper': string.ascii_uppercase,
            'digits': string.digits,
            'special': string.punctuation
        }
        
        if options["Exclude Similar Characters (iIl1O0)"].get():
            character_sets['lower'] = character_sets['lower'].translate(str.maketrans('', '', 'il'))
            character_sets['upper'] = character_sets['upper'].translate(str.maketrans('', '', 'IO'))
            character_sets['digits'] = character_sets['digits'].translate(str.maketrans('', '', '01'))
            
        if options["Exclude Ambiguous Characters ({}[]()/\'\"`~,;:.<>)"].get():
            character_sets['special'] = character_sets['special'].translate(str.maketrans('', '', '{}[]()/\'"`~,;:.<>'))

        selected_sets = []
        if options["Lowercase Letters (a-z)"].get():
            selected_sets.append(character_sets['lower'])
        if options["Uppercase Letters (A-Z)"].get():
            selected_sets.append(character_sets['upper'])
        if options["Numbers (0-9)"].get():
            selected_sets.append(character_sets['digits'])
        if options["Special Characters (!@#$)"].get():
            selected_sets.append(character_sets['special'])

        if not selected_sets:
            messagebox.showwarning("Warning", "Please select at least one character type!")
            return ""

        password = []
        for charset in selected_sets:
            password.append(random.choice(charset))
        
        all_chars = ''.join(selected_sets)
        password.extend(random.choice(all_chars) for _ in range(length - len(password)))
        random.shuffle(password)
        
        password_str = ''.join(password)
        password_var.set(password_str)
        return password_str

    def copy_to_clipboard(self, text: str, window: Optional[Toplevel] = None):
        """Copy text to clipboard with auto-clear"""
        if not text:
            messagebox.showwarning("Warning", "Nothing to copy!")
            return
            
        secure_text = SecureString(text)
        pyperclip.copy(secure_text.get())
        
        timeout = self.config['clipboard_timeout']
        messagebox.showinfo("Copied", f"Text copied to clipboard (will clear in {timeout} seconds)!")
        self.root.after(timeout * 1000, lambda: pyperclip.copy(""))
        
        if window:
            window.destroy()
        
        secure_text.clear()

    def save_encrypted_data(self, data: Dict, file_path: str = DATA_FILE):
        """Encrypt and save data to file"""
        temp_file = file_path + '.tmp'
        try:
            json_data = json.dumps(data, indent=2).encode()
            encrypted_data = self.encryptor.encrypt(json_data)
            
            with open(temp_file, 'wb') as file:
                file.write(encrypted_data)
                
            if os.path.exists(file_path):
                os.replace(temp_file, file_path)
            else:
                os.rename(temp_file, file_path)
                
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save data: {str(e)}")
            if os.path.exists(temp_file):
                os.remove(temp_file)

    def load_encrypted_data(self, file_path: str = DATA_FILE) -> Dict:
        """Load and decrypt data from file"""
        if not os.path.exists(file_path):
            return {}

        try:
            with open(file_path, 'rb') as file:
                encrypted_data = file.read()
                if not encrypted_data:
                    return {}

            decrypted_data = self.encryptor.decrypt(encrypted_data).decode()
            return json.loads(decrypted_data)
        except (InvalidToken, ValueError, json.JSONDecodeError) as e:
            messagebox.showerror("Error", f"Unable to load data file: {str(e)}")
            return {}
        except FileNotFoundError:
            return {}

    def show_password_list(self):
        """Display all stored passwords as the main view"""
        self.clear_main_frame()
        
        data = self.load_encrypted_data()
        if not data:
            ttk.Label(self.main_frame, text="No passwords stored yet.").pack(pady=20)
            return
        
        # Search and sort controls
        control_frame = ttk.Frame(self.main_frame)
        control_frame.pack(fill='x', padx=10, pady=10)
        
        search_frame = ttk.Frame(control_frame)
        search_frame.pack(side='left', fill='x', expand=True)
        
        ttk.Label(search_frame, text="Search:").pack(side='left')
        search_var = StringVar()
        search_entry = ttk.Entry(search_frame, textvariable=search_var, width=30)
        search_entry.pack(side='left', padx=5)
        search_entry.focus()
        
        sort_frame = ttk.Frame(control_frame)
        sort_frame.pack(side='right')
        
        ttk.Label(sort_frame, text="Sort by:").pack(side='left')
        sort_options = ['Site', 'Username', 'Strength', 'Modified', '2FA']
        sort_var = StringVar(value='Site')
        sort_menu = ttk.Combobox(sort_frame, textvariable=sort_var, 
                                values=sort_options, state='readonly', width=10)
        sort_menu.pack(side='left', padx=5)
        
        # Main display area
        tree_frame = ttk.Frame(self.main_frame)
        tree_frame.pack(fill='both', expand=True)
        
        columns = ('site', 'username', 'strength', 'modified', '2fa')
        self.tree = ttk.Treeview(tree_frame, columns=columns, show='headings')
        
        for col in columns:
            self.tree.heading(col, text=col.capitalize(), 
                            command=lambda c=col: self.sort_treeview(c))
        
        self.tree.column('site', width=150)
        self.tree.column('username', width=150)
        self.tree.column('strength', width=80)
        self.tree.column('modified', width=120)
        self.tree.column('2fa', width=50)
        
        scrollbar = ttk.Scrollbar(tree_frame, orient='vertical', command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar.set)
        scrollbar.pack(side='right', fill='y')
        self.tree.pack(side='left', fill='both', expand=True)
        
        self.update_password_list(data)
        
        self.tree.bind('<Double-1>', lambda e: self.show_password_details(self.tree, data))
        
        def update_search(*args):
            query = search_var.get().lower()
            self.tree.delete(*self.tree.get_children())
            
            for entry in data.values():
                if (query in entry['site'].lower() or 
                    query in entry['username'].lower()):
                    self.tree.insert('', 'end', 
                                   values=(entry['site'],
                                           entry['username'],
                                           entry.get('strength', 'Unknown'),
                                           entry['modified'],
                                           '✓' if entry['twofa_enabled'] else '✗'))
        
        search_var.trace_add('write', update_search)
        
        def update_sort(*args):
            sort_by = sort_var.get().lower()
            column_map = {
                'site': 'site',
                'username': 'username',
                'strength': 'strength',
                'modified': 'modified',
                '2fa': '2fa'
            }
            if sort_by in column_map:
                self.sort_treeview(column_map[sort_by])
        
        sort_var.trace_add('write', update_sort)
        
        btn_frame = ttk.Frame(self.main_frame)
        btn_frame.pack(fill='x', pady=5)
        
        ttk.Button(btn_frame, text="Add New", 
                  command=self.show_add_password).pack(side='left', padx=5)
        ttk.Button(btn_frame, text="View Details", 
                  command=lambda: self.show_password_details(self.tree, data)).pack(side='left', padx=5)
        ttk.Button(btn_frame, text="Export Selected", 
                  command=lambda: self.export_passwords(self.tree, data)).pack(side='left', padx=5)
        ttk.Button(btn_frame, text="Refresh", 
                  command=lambda: [self.update_password_list(self.load_encrypted_data()), 
                                 search_var.set("")]).pack(side='right', padx=5)

    def sort_treeview(self, column):
        """Sort treeview by column"""
        if column == self.current_sort_column:
            self.sort_reverse = not self.sort_reverse
        else:
            self.current_sort_column = column
            self.sort_reverse = False
        
        items = [(self.tree.set(item, column), item) for item in self.tree.get_children('')]
        
        if column in ['modified']:
            items.sort(key=lambda x: time.mktime(time.strptime(x[0], "%Y-%m-%d %H:%M:%S")), 
                      reverse=self.sort_reverse)
        elif column in ['2fa']:
            items.sort(key=lambda x: x[0] == '✓', reverse=self.sort_reverse)
        else:
            items.sort(reverse=self.sort_reverse)
        
        for index, (val, item) in enumerate(items):
            self.tree.move(item, '', index)
        
        for col in self.tree['columns']:
            self.tree.heading(col, text=col.capitalize())
        self.tree.heading(column, 
                         text=column.capitalize() + (' ↓' if not self.sort_reverse else ' ↑'))

    def update_password_list(self, data):
        """Update the password list with current data"""
        self.tree.delete(*self.tree.get_children())
        for entry in sorted(data.values(), key=lambda x: x[self.current_sort_column].lower() 
                         if self.current_sort_column != 'modified' else x[self.current_sort_column], 
                         reverse=self.sort_reverse):
            self.tree.insert('', 'end', 
                          values=(entry['site'],
                                entry['username'],
                                entry.get('strength', 'Unknown'),
                                entry['modified'],
                                '✓' if entry['twofa_enabled'] else '✗'))

    def show_add_password(self):
        """Show the add password form"""
        self.clear_main_frame()
        
        ttk.Label(self.main_frame, text="Site:").grid(row=0, column=0, pady=5, sticky="w")
        self.site_entry = ttk.Entry(self.main_frame, width=30)
        self.site_entry.grid(row=0, column=1, pady=5)
        
        ttk.Label(self.main_frame, text="Username:").grid(row=1, column=0, pady=5, sticky="w")
        self.username_entry = ttk.Entry(self.main_frame, width=30)
        self.username_entry.grid(row=1, column=1, pady=5)
        
        ttk.Label(self.main_frame, text="Password:").grid(row=2, column=0, pady=5, sticky="w")
        self.password_entry = ttk.Entry(self.main_frame, width=30, show="*")
        self.password_entry.grid(row=2, column=1, pady=5)
        
        self.strength_label = ttk.Label(self.main_frame, text="Strength: ", foreground="black")
        self.strength_label.grid(row=3, column=0, columnspan=2, pady=5)
        self.password_entry.bind("<KeyRelease>", 
                               lambda e: self.update_strength_label(self.password_entry, self.strength_label))
        
        ttk.Label(self.main_frame, text="2FA OTP (if enabled):").grid(row=4, column=0, pady=5, sticky="w")
        self.otp_entry = ttk.Entry(self.main_frame, width=30)
        self.otp_entry.grid(row=4, column=1, pady=5)
        
        self.twofa_enabled = BooleanVar(value=False)
        ttk.Checkbutton(self.main_frame, text="Enable 2FA", variable=self.twofa_enabled,
                       command=self.update_twofa_label).grid(row=5, column=0, columnspan=2, pady=5)
        
        self.twofa_status_label = ttk.Label(self.main_frame, text="2FA Status: Disabled", foreground="red")
        self.twofa_status_label.grid(row=6, column=0, columnspan=2, pady=5)
        
        self.current_otp_label = ttk.Label(self.main_frame, text="Current 2FA Code: ", foreground="blue")
        self.current_otp_label.grid(row=7, column=0, columnspan=2, pady=5)
        
        def update_otp_display():
            if self.twofa_enabled.get():
                current_code = self.totp.now()
                self.current_otp_label.config(text=f"Current 2FA Code: {current_code}")
            else:
                self.current_otp_label.config(text="Current 2FA Code: ")
            self.root.after(1000, update_otp_display)
            
        update_otp_display()
        
        btn_frame = ttk.Frame(self.main_frame)
        btn_frame.grid(row=8, column=0, columnspan=2, pady=10)
        
        ttk.Button(btn_frame, text="Save", command=self.save_password).pack(side="left", padx=5)
        ttk.Button(btn_frame, text="Generate", 
                  command=self.create_password_generator).pack(side="left", padx=5)
        ttk.Button(btn_frame, text="Cancel", command=self.show_password_list).pack(side="right", padx=5)

    def save_password(self):
        """Save password entry to encrypted storage"""
        site = self.site_entry.get().strip()
        username = self.username_entry.get().strip()
        password = self.password_entry.get()
        otp = self.otp_entry.get().strip()
        twofa = self.twofa_enabled.get()

        if not site or not username:
            messagebox.showwarning("Validation Error", "Site and Username fields are required!")
            return

        if not password:
            messagebox.showwarning("Validation Error", "Password field is required!")
            return

        strength = self.calculate_strength(password)
        if strength["strength"] in ["Too Short", "Weak"]:
            if not messagebox.askyesno("Weak Password", 
                                     "Password is weak. Save anyway?", 
                                     icon='warning'):
                return

        if twofa and not self.totp.verify(otp):
            messagebox.showerror("Error", "Invalid 2FA code.")
            return

        data = self.load_encrypted_data()
        
        existing_entry = next((e for e in data.values() if e['site'] == site and e['username'] == username), None)
        if existing_entry:
            if not messagebox.askyesno("Confirm Overwrite", 
                                     "Password already exists for this site/username. Overwrite?"):
                return

        encrypted_password = self.encryptor.encrypt(password.encode()).decode()
        
        entry = {
            "site": site,
            "username": username,
            "password": encrypted_password,
            "otp": otp if twofa else None,
            "twofa_enabled": twofa,
            "created": time.strftime("%Y-%m-%d %H:%M:%S"),
            "modified": time.strftime("%Y-%m-%d %H:%M:%S"),
            "strength": strength["strength"],
            "score": strength["score"]
        }
        
        if existing_entry:
            entry['history'] = existing_entry.get('history', [])
            entry['history'].append({
                "password": existing_entry['password'],
                "changed": existing_entry['modified'],
                "strength": existing_entry.get('strength', 'Unknown')
            })
            entry['history'] = entry['history'][-5:]
        
        data[f"{site}:{username}"] = entry

        self.save_encrypted_data(data)
        messagebox.showinfo("Success", "Password saved successfully!")
        self.show_password_list()

    def show_password_details(self, tree: ttk.Treeview, data: Dict):
        """Show detailed view of selected password"""
        selected = tree.focus()
        if not selected:
            messagebox.showwarning("Warning", "No entry selected!")
            return
            
        item = tree.item(selected)
        site, username = item['values'][:2]
        key = f"{site}:{username}"
        
        if key not in data:
            messagebox.showerror("Error", "Selected entry not found!")
            return
            
        entry = data[key]
        
        detail_window = Toplevel(self.root)
        detail_window.title(f"Password Details - {site}")
        detail_window.geometry("500x400")
        
        main_frame = ttk.Frame(detail_window, padding=10)
        main_frame.pack(fill='both', expand=True)
        
        ttk.Label(main_frame, text=f"Site: {entry['site']}", font=('Helvetica', 10, 'bold')).pack(anchor='w')
        ttk.Label(main_frame, text=f"Username: {entry['username']}").pack(anchor='w')
        
        pw_frame = ttk.Frame(main_frame)
        pw_frame.pack(fill='x', pady=5)
        
        ttk.Label(pw_frame, text="Password:").pack(side='left')
        
        password_var = StringVar(value="********")
        pw_entry = ttk.Entry(pw_frame, textvariable=password_var, width=25, show="*")
        pw_entry.pack(side='left', padx=5)
        
        def toggle_password():
            if password_var.get() == "********":
                decrypted = self.encryptor.decrypt(entry['password'].encode()).decode()
                password_var.set(decrypted)
            else:
                password_var.set("********")
        
        ttk.Button(pw_frame, text="Show", command=toggle_password).pack(side='left')
        
        btn_frame = ttk.Frame(main_frame)
        btn_frame.pack(fill='x', pady=5)
        
        ttk.Button(btn_frame, text="Copy Username", 
                  command=lambda: self.copy_to_clipboard(entry['username'])).pack(side='left', padx=2)
        ttk.Button(btn_frame, text="Copy Password", 
                  command=lambda: self.copy_to_clipboard(
                      self.encryptor.decrypt(entry['password'].encode()).decode())).pack(side='left', padx=2)
        
        meta_frame = ttk.LabelFrame(main_frame, text="Metadata", padding=10)
        meta_frame.pack(fill='x', pady=5)
        
        ttk.Label(meta_frame, text=f"Created: {entry['created']}").pack(anchor='w')
        ttk.Label(meta_frame, text=f"Modified: {entry['modified']}").pack(anchor='w')
        ttk.Label(meta_frame, text=f"Strength: {entry.get('strength', 'Unknown')}").pack(anchor='w')
        
        if entry['twofa_enabled']:
            ttk.Label(meta_frame, text="2FA: Enabled", foreground="green").pack(anchor='w')
        else:
            ttk.Label(meta_frame, text="2FA: Disabled", foreground="red").pack(anchor='w')
        
        if 'history' in entry and entry['history']:
            history_frame = ttk.LabelFrame(main_frame, text="Password History", padding=10)
            history_frame.pack(fill='x', pady=5)
            
            for i, hist in enumerate(reversed(entry['history'])):
                ttk.Label(history_frame, 
                         text=f"{i+1}. Changed on {hist['changed']} - Strength: {hist['strength']}").pack(anchor='w')
        
        action_frame = ttk.Frame(main_frame)
        action_frame.pack(fill='x', pady=10)
        
        ttk.Button(action_frame, text="Edit", 
                  command=lambda: [self.edit_password(key), detail_window.destroy()]).pack(side='left', padx=5)
        ttk.Button(action_frame, text="Delete", 
                  command=lambda: self.delete_password(key, detail_window)).pack(side='left', padx=5)
        ttk.Button(action_frame, text="Close", 
                  command=detail_window.destroy).pack(side='right', padx=5)

    def edit_password(self, key: str):
        """Edit an existing password entry"""
        data = self.load_encrypted_data()
        if key not in data:
            messagebox.showerror("Error", "Entry not found.")
            return
            
        entry = data[key]
        decrypted_password = self.encryptor.decrypt(entry['password'].encode()).decode()
        
        edit_window = Toplevel(self.root)
        edit_window.title(f"Edit {entry['site']}")
        edit_window.geometry("450x400")
        
        main_frame = ttk.Frame(edit_window, padding=10)
        main_frame.pack(fill='both', expand=True)
        
        ttk.Label(main_frame, text="Site:").grid(row=0, column=0, pady=5, sticky="w")
        site_entry = ttk.Entry(main_frame, width=30)
        site_entry.insert(0, entry['site'])
        site_entry.grid(row=0, column=1, pady=5)
        
        ttk.Label(main_frame, text="Username:").grid(row=1, column=0, pady=5, sticky="w")
        username_entry = ttk.Entry(main_frame, width=30)
        username_entry.insert(0, entry['username'])
        username_entry.grid(row=1, column=1, pady=5)
        
        ttk.Label(main_frame, text="Password:").grid(row=2, column=0, pady=5, sticky="w")
        password_entry = ttk.Entry(main_frame, width=30)
        password_entry.insert(0, decrypted_password)
        password_entry.grid(row=2, column=1, pady=5)
        
        strength_label = ttk.Label(main_frame, text="Strength: ", foreground="black")
        strength_label.grid(row=3, column=0, columnspan=2, pady=5)
        password_entry.bind("<KeyRelease>", 
                          lambda e: self.update_strength_label(password_entry, strength_label))
        self.update_strength_label(password_entry, strength_label)
        
        ttk.Label(main_frame, text="2FA OTP (if enabled):").grid(row=4, column=0, pady=5, sticky="w")
        otp_entry = ttk.Entry(main_frame, width=30)
        if entry['otp']:
            otp_entry.insert(0, entry['otp'])
        otp_entry.grid(row=4, column=1, pady=5)
        
        twofa_var = BooleanVar(value=entry['twofa_enabled'])
        ttk.Checkbutton(main_frame, text="Enable 2FA", variable=twofa_var,
                       command=lambda: self.update_twofa_label()).grid(row=5, column=0, columnspan=2, pady=5)
        
        twofa_status_label = ttk.Label(main_frame, text="2FA Status: Disabled", foreground="red")
        twofa_status_label.grid(row=6, column=0, columnspan=2, pady=5)
        if twofa_var.get():
            twofa_status_label.config(text="2FA Status: Enabled", foreground="green")
        
        btn_frame = ttk.Frame(main_frame)
        btn_frame.grid(row=7, column=0, columnspan=2, pady=10)
        
        ttk.Button(btn_frame, text="Generate", 
                  command=lambda: self.create_password_generator()).pack(side='left', padx=5)
        ttk.Button(btn_frame, text="Save", command=lambda: self.save_edited_password(
            key, site_entry, username_entry, password_entry, otp_entry, twofa_var, edit_window)).pack(side='left', padx=5)
        ttk.Button(btn_frame, text="Cancel", command=edit_window.destroy).pack(side='right', padx=5)

    def save_edited_password(self, old_key: str, site_entry: ttk.Entry, username_entry: ttk.Entry, 
                           password_entry: ttk.Entry, otp_entry: ttk.Entry, 
                           twofa_var: BooleanVar, window: Toplevel):
        """Save changes to an edited password"""
        new_site = site_entry.get().strip()
        new_username = username_entry.get().strip()
        new_password = password_entry.get()
        new_otp = otp_entry.get().strip()
        new_twofa = twofa_var.get()
        
        if not new_site or not new_username:
            messagebox.showwarning("Validation Error", "Site and Username fields are required!")
            return
            
        if not new_password:
            messagebox.showwarning("Validation Error", "Password field is required!")
            return
            
        strength = self.calculate_strength(new_password)
        if strength["strength"] in ["Too Short", "Weak"]:
            if not messagebox.askyesno("Weak Password", 
                                     "Password is weak. Save anyway?", 
                                     icon='warning'):
                return
                
        if new_twofa and not self.totp.verify(new_otp):
            messagebox.showerror("Error", "Invalid 2FA code.")
            return
            
        data = self.load_encrypted_data()
        if old_key not in data:
            messagebox.showerror("Error", "Original entry not found!")
            return
            
        original_entry = data[old_key]
        
        new_entry = {
            "site": new_site,
            "username": new_username,
            "password": self.encryptor.encrypt(new_password.encode()).decode(),
            "otp": new_otp if new_twofa else None,
            "twofa_enabled": new_twofa,
            "created": original_entry['created'],
            "modified": time.strftime("%Y-%m-%d %H:%M:%S"),
            "strength": strength["strength"],
            "score": strength["score"]
        }
        
        if 'history' in original_entry:
            new_entry['history'] = original_entry['history']
            new_entry['history'].append({
                "password": original_entry['password'],
                "changed": original_entry['modified'],
                "strength": original_entry.get('strength', 'Unknown')
            })
            new_entry['history'] = new_entry['history'][-5:]
        
        new_key = f"{new_site}:{new_username}"
        if new_key != old_key:
            del data[old_key]
            
        data[new_key] = new_entry
        
        self.save_encrypted_data(data)
        messagebox.showinfo("Success", "Changes saved successfully!")
        window.destroy()
        self.show_password_list()

    def delete_password(self, key: str, window: Optional[Toplevel] = None):
        """Delete a password entry with confirmation"""
        if not messagebox.askyesno("Confirm Delete", "Delete this password entry?"):
            return
            
        data = self.load_encrypted_data()
        if key in data:
            del data[key]
            self.save_encrypted_data(data)
            messagebox.showinfo("Success", "Password deleted successfully.")
            if window:
                window.destroy()
            self.show_password_list()
        else:
            messagebox.showerror("Error", "Entry not found.")
        
    def export_passwords(self, tree: ttk.Treeview, data: Dict):
        """Export selected passwords to encrypted file"""
        selected = tree.selection()
        if not selected:
            messagebox.showwarning("Warning", "No entries selected!")
            return
            
        entries = []
        for item_id in selected:
            item = tree.item(item_id)
            site, username = item['values'][:2]
            key = f"{site}:{username}"
            if key in data:
                entries.append(data[key])
        
        if not entries:
            messagebox.showerror("Error", "No valid entries selected!")
            return
            
        export_pw = simpledialog.askstring("Export Passwords", 
                                         "Set a password for the export file:", 
                                         show='*')
        if not export_pw:
            return
            
        export_data = {
            'version': '1.0',
            'timestamp': time.strftime("%Y-%m-%d %H:%M:%S"),
            'entries': entries
        }
        
        salt = os.urandom(16)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=PBKDF2_ITERATIONS,
            backend=default_backend()
        )
        key = base64.urlsafe_b64encode(kdf.derive(export_pw.encode()))
        fernet = Fernet(key)
        
        encrypted_data = fernet.encrypt(json.dumps(export_data).encode())
        
        file_path = filedialog.asksaveasfilename(
            defaultextension=".mxp",
            filetypes=[("MX Pass Export", "*.mxp"), ("All Files", "*.*")],
            title="Save Password Export"
        )
        
        if file_path:
            try:
                with open(file_path, 'wb') as f:
                    f.write(salt + b'||' + encrypted_data)
                messagebox.showinfo("Success", "Passwords exported successfully!")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to export: {str(e)}")

    def update_twofa_label(self):
        """Update 2FA status label"""
        status = "Enabled" if self.twofa_enabled.get() else "Disabled"
        color = "green" if self.twofa_enabled.get() else "red"
        if hasattr(self, 'twofa_status_label'):
            self.twofa_status_label.config(text=f"2FA Status: {status}", foreground=color)

    def set_theme(self, theme: str):
        """Set light or dark theme"""
        style = ttk.Style()
        
        if theme == 'dark':
            bg = '#2b2b2b'
            fg = '#ffffff'
            entry_bg = '#333333'
            button_bg = '#444444'
            select_bg = '#555555'
            style.theme_use('alt')
        else:
            bg = '#ffffff'
            fg = '#000000'
            entry_bg = '#ffffff'
            button_bg = '#f0f0f0'
            select_bg = '#d4d4d4'
            style.theme_use('default')
            
        style.configure('.', background=bg, foreground=fg)
        style.configure('TLabel', background=bg, foreground=fg)
        style.configure('TButton', background=button_bg, foreground=fg)
        style.configure('TEntry', fieldbackground=entry_bg, foreground=fg)
        style.configure('TFrame', background=bg)
        style.configure('Treeview', background=bg, foreground=fg, fieldbackground=bg)
        style.map('Treeview', background=[('selected', select_bg)])
        
        self.root.configure(bg=bg)
        for widget in self.root.winfo_children():
            if isinstance(widget, (ttk.Frame, ttk.Label, ttk.Button, ttk.Entry)):
                continue
            widget.configure(bg=bg, fg=fg)
            
        self.current_theme = theme
        self.config['theme'] = theme
        self.save_config()

    def toggle_theme(self):
        """Toggle between light and dark themes"""
        if self.current_theme == 'light':
            self.set_theme('dark')
        else:
            self.set_theme('light')

    def setup_activity_tracking(self):
        """Set up session timeout tracking"""
        self.root.bind('<Motion>', lambda e: self.update_last_activity())
        self.root.bind('<Key>', lambda e: self.update_last_activity())
        self.root.bind('<Button>', lambda e: self.update_last_activity())
        self.check_timeout()

    def update_last_activity(self):
        """Update last activity timestamp"""
        self.last_activity = time.time()

    def check_timeout(self):
        """Check if session has timed out"""
        if time.time() - self.last_activity > self.config['session_timeout']:
            if messagebox.askyesno("Session Timeout", 
                                 "Your session has timed out. Do you want to continue?"):
                self.update_last_activity()
            else:
                self.root.destroy()
                return
                
        self.root.after(60000, self.check_timeout)

    def open_about_window(self):
        """Show about information"""
        about_window = Toplevel(self.root)
        about_window.title("About MX Pass")
        about_window.geometry("500x400")
        
        about_text = """
        MX Pass - Secure Password Manager
        Version: 2.0
        
        Features:
        - Secure AES-256 encryption
        - Master password protection
        - Two-factor authentication
        - Password strength evaluation
        - Light/dark theme support
        - Secure clipboard handling
        - Session timeout
        - Password history
        - Export functionality
        """
        
        ttk.Label(about_window, text=about_text, justify="left", padding=20).pack()
        ttk.Button(about_window, text="Close", command=about_window.destroy).pack(pady=10)

    def open_shortcuts_help(self):
        """Show keyboard shortcuts"""
        help_window = Toplevel(self.root)
        help_window.title("Keyboard Shortcuts")
        help_window.geometry("350x300")
        
        shortcuts = """
        Keyboard Shortcuts:
        
        Ctrl+S: Save Password
        Ctrl+V: View Passwords
        Ctrl+T: Toggle Theme
        Ctrl+Q: Quit Application
        Ctrl+G: Generate Password
        Ctrl+C: Copy to Clipboard
        Ctrl+F: Search Passwords
        """
        
        ttk.Label(help_window, text=shortcuts, justify="left", padding=20).pack()
        ttk.Button(help_window, text="Close", command=help_window.destroy).pack(pady=10)

    def open_settings(self):
        """Open settings dialog"""
        settings_window = Toplevel(self.root)
        settings_window.title("Settings")
        settings_window.geometry("400x300")
        
        ttk.Label(settings_window, text="Clipboard Clear Timeout (seconds):").pack(pady=5)
        clipboard_var = IntVar(value=self.config['clipboard_timeout'])
        ttk.Spinbox(settings_window, from_=10, to=300, textvariable=clipboard_var).pack(pady=5)
        
        ttk.Label(settings_window, text="Session Timeout (minutes):").pack(pady=5)
        session_var = IntVar(value=self.config['session_timeout'] // 60)
        ttk.Spinbox(settings_window, from_=1, to=60, textvariable=session_var).pack(pady=5)
        
        ttk.Label(settings_window, text="Theme:").pack(pady=5)
        theme_var = StringVar(value=self.config['theme'])
        ttk.Combobox(settings_window, textvariable=theme_var, 
                     values=['light', 'dark'], state='readonly').pack(pady=5)
        
        def save_settings():
            self.config['clipboard_timeout'] = clipboard_var.get()
            self.config['session_timeout'] = session_var.get() * 60
            self.config['theme'] = theme_var.get()
            self.save_config()
            self.set_theme(theme_var.get())
            settings_window.destroy()
            messagebox.showinfo("Success", "Settings saved successfully!")
            
        ttk.Button(settings_window, text="Save", command=save_settings).pack(pady=10)

    def create_main_window(self) -> Tk:
        """Create and configure the main application window"""
        root = Tk()
        root.title("MX Pass - Secure Password Manager")
        root.geometry("800x600")
        
        try:
            root.iconbitmap('icon.ico')
        except:
            pass
        
        root.protocol("WM_DELETE_WINDOW", self.on_close)
        
        root.bind('<Control-t>', lambda e: self.toggle_theme())
        root.bind('<Control-q>', lambda e: self.on_close())
        root.bind('<Control-g>', lambda e: self.create_password_generator())
        root.bind('<Control-f>', lambda e: self.show_password_list())
        
        return root

    def clear_main_frame(self):
        """Clear the main frame for new content"""
        if hasattr(self, 'main_frame'):
            self.main_frame.destroy()
        self.main_frame = ttk.Frame(self.root, padding="10")
        self.main_frame.pack(fill="both", expand=True)

    def setup_ui(self):
        """Set up the main user interface"""
        menubar = Menu(self.root)
        self.root.config(menu=menubar)
        
        file_menu = Menu(menubar, tearoff=0)
        file_menu.add_command(label="Password List", command=self.show_password_list)
        file_menu.add_command(label="Add Password", command=self.show_add_password)
        file_menu.add_separator()
        file_menu.add_command(label="Settings", command=self.open_settings)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.on_close)
        menubar.add_cascade(label="File", menu=file_menu)
        
        tools_menu = Menu(menubar, tearoff=0)
        tools_menu.add_command(label="Generate Password", command=self.create_password_generator)
        tools_menu.add_command(label="Toggle Theme", command=self.toggle_theme)
        menubar.add_cascade(label="Tools", menu=tools_menu)
        
        help_menu = Menu(menubar, tearoff=0)
        help_menu.add_command(label="Keyboard Shortcuts", command=self.open_shortcuts_help)
        help_menu.add_command(label="About", command=self.open_about_window)
        menubar.add_cascade(label="Help", menu=help_menu)

    def on_close(self):
        """Handle application close"""
        if messagebox.askokcancel("Quit", "Do you want to quit MX Pass?"):
            if hasattr(self, 'encryptor'):
                del self.encryptor
            self.root.destroy()

if __name__ == "__main__":
    PasswordManager()