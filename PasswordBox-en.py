import sqlite3
import tkinter as tk
from tkinter import ttk, messagebox, simpledialog
import random
import string
import pyperclip
import base64
import os
import hashlib
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet
import threading 

DB_NAME = "PasswordBox.db"

# --- Encryption Helper Functions ---
def generate_key(master_password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(master_password.encode()))
    return key

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def init_db():
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS settings (
                    id INTEGER PRIMARY KEY, 
                    salt BLOB,
                    master_hash TEXT
                )''')
    c.execute('''CREATE TABLE IF NOT EXISTS passwords (
                    id INTEGER PRIMARY KEY,
                    title TEXT,
                    username TEXT,
                    password BLOB,
                    link TEXT,
                    notes TEXT,
                    category TEXT
                )''')
    
    c.execute("SELECT salt FROM settings WHERE id = 1")
    if not c.fetchone():
        salt = os.urandom(16)
        c.execute("INSERT INTO settings (id, salt, master_hash) VALUES (1, ?, ?)", 
                  (salt, None))
    
    conn.commit()
    conn.close()

def generate_password(length=16):
    lowercase = string.ascii_lowercase
    uppercase = string.ascii_uppercase
    digits = string.digits
    special = "!@#$%&*+?="
    
    password = [
        random.choice(uppercase),
        random.choice(lowercase),
        random.choice(digits),
        random.choice(special)
    ]
    
    all_chars = lowercase + uppercase + digits + special
    password += random.choices(all_chars, k=length-4)
    random.shuffle(password)
    return ''.join(password)

class PasswordManagerApp:
    def __init__(self, root, cipher_suite):
        self.root = root
        self.cipher_suite = cipher_suite
        self.root.title("PasswordBox")
        self.root.geometry("1200x650")
        self.root.minsize(900, 500)

        self.search_var = tk.StringVar()
        self.password_visible = tk.BooleanVar(value=False)
        self.search_var.trace("w", lambda *args: self.load_data())

        # UI Construction
        main_frame = tk.Frame(root, bg="white")
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        top_frame = tk.Frame(main_frame, bg="white")
        top_frame.pack(fill=tk.X, pady=(0, 10))
        
        tk.Label(top_frame, text="🔍 Search:", font=("Arial", 10, "bold"), bg="white").pack(side=tk.LEFT, padx=5)
        search_entry = tk.Entry(top_frame, textvariable=self.search_var, width=50, font=("Arial", 10))
        search_entry.pack(side=tk.LEFT, padx=5)

        tree_frame = tk.Frame(main_frame)
        tree_frame.pack(fill=tk.BOTH, expand=True)

        self.tree = ttk.Treeview(
            tree_frame, 
            columns=("Title", "Username", "Password", "Category", "Link", "Notes"), 
            show="headings",
            selectmode="browse"
        )
        
        column_widths = {
            "Title": 150, "Username": 140, "Password": 150,
            "Category": 120, "Link": 180, "Notes": 180
        }
        
        for col in self.tree["columns"]:
            self.tree.heading(col, text=col)
            self.tree.column(col, width=column_widths[col])

        scrollbar = ttk.Scrollbar(tree_frame, orient=tk.VERTICAL, command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar.set)
        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        self.tree.bind("<Double-1>", lambda e: self.edit_entry())

        btn_frame = tk.Frame(main_frame, bg="white")
        btn_frame.pack(pady=15)
        tk.Checkbutton(
            top_frame,
            text="👁 Show Passwords",
            variable=self.password_visible,
            command=self.load_data,
            bg="white",
            font=("Arial", 9, "bold")
        ).pack(side=tk.RIGHT, padx=10)

        buttons = [
            ("➕ Add New", self.add_entry, "#4CAF50"),
            ("✏️ Edit", self.edit_entry, "#2196F3"),
            ("🗑️ Delete", self.delete_entry, "#f44336"),
            ("🔑 Copy Password", lambda: self.copy_to_clipboard("password"), "#FF9800"),
            ("👤 Copy Username", lambda: self.copy_to_clipboard("username"), "#9C27B0")
        ]

        for text, cmd, color in buttons:
            tk.Button(btn_frame, text=text, command=cmd, width=18, bg=color, fg="white",
                      font=("Arial", 9, "bold"), cursor="hand2", relief=tk.RAISED).pack(side=tk.LEFT, padx=5)

        status_frame = tk.Frame(root, bg="#f0f0f0")
        status_frame.pack(side=tk.BOTTOM, fill=tk.X)
        
        self.status_label = tk.Label(status_frame, text="Loading...", font=("Arial", 9), fg="gray", bg="#f0f0f0")
        self.status_label.pack(pady=5)

        self.load_data()

    def get_db_connection(self):
        return sqlite3.connect(DB_NAME)

    def load_data(self):
        for row in self.tree.get_children():
            self.tree.delete(row)
        
        search_term = f"%{self.search_var.get().lower()}%"
        conn = self.get_db_connection()
        c = conn.cursor()
        c.execute("""SELECT id, title, username, password, category, link, notes 
                     FROM passwords WHERE LOWER(title) LIKE ? OR LOWER(category) LIKE ? OR LOWER(username) LIKE ?
                     ORDER BY title""", (search_term, search_term, search_term))
        
        count = 0
        for row in c.fetchall():
            try:
                dec_pw = self.cipher_suite.decrypt(row[3]).decode()

                if self.password_visible.get():
                    password_display = dec_pw
                else:
                    password_display = "••••••••"
            except:
                password_display = "❌ Error"
            
            self.tree.insert("", tk.END, iid=row[0], values=(row[1], row[2], password_display, row[4], row[5], row[6]))
            count += 1
        
        conn.close()
        self.status_label.config(text=f"Protected Mode | Entries: {count}", fg="gray")

    def copy_to_clipboard(self, type):
        selected_id = self.tree.focus()
        if not selected_id:
            return messagebox.showwarning("Warning", "Please select an entry!")

        try:
            with self.get_db_connection() as conn:
                c = conn.cursor()
                if type == "password":
                    c.execute("SELECT password FROM passwords WHERE id=?", (selected_id,))
                    value = self.cipher_suite.decrypt(c.fetchone()[0]).decode()
                    label_text = "Password"
                else:
                    c.execute("SELECT username FROM passwords WHERE id=?", (selected_id,))
                    value = c.fetchone()[0]
                    label_text = "Username"

            if value:
                pyperclip.copy(value)
                self.status_label.config(
                    text=f"✅ {label_text} copied (will clear in 30s)",
                    fg="#2E7D32"
                )

                # SECURE CLIPBOARD CLEARING
                self.root.after(30000, self.clear_clipboard)

        except Exception as e:
            messagebox.showerror("Error", str(e))

    def clear_clipboard(self):
        try:
            pyperclip.copy("")
            self.status_label.config(
                text="ℹ️ Clipboard cleared for security reasons.",
                fg="gray"
            )
        except:
            pass

    def add_entry(self):
        dialog = EntryWindow(self.root, "Add New Entry")
        self.root.wait_window(dialog.top)
        if dialog.saved:
            try:
                enc_password = self.cipher_suite.encrypt(dialog.password.encode())
                conn = self.get_db_connection()
                c = conn.cursor()
                c.execute("INSERT INTO passwords (title, username, password, link, notes, category) VALUES (?,?,?,?,?,?)",
                          (dialog.title, dialog.username, enc_password, dialog.link, dialog.notes, dialog.category))
                conn.commit()
                conn.close()
                self.load_data()
            except Exception as e:
                messagebox.showerror("Error", str(e))

    def edit_entry(self):
        selected_id = self.tree.focus()
        if not selected_id: return
        conn = self.get_db_connection()
        c = conn.cursor()
        c.execute("SELECT title, username, password, link, notes, category FROM passwords WHERE id=?", (selected_id,))
        data = list(c.fetchone())
        data[2] = self.cipher_suite.decrypt(data[2]).decode()
        dialog = EntryWindow(self.root, "Edit Entry", *data)
        self.root.wait_window(dialog.top)
        if dialog.saved:
            enc_pw = self.cipher_suite.encrypt(dialog.password.encode())
            c.execute("UPDATE passwords SET title=?, username=?, password=?, link=?, notes=?, category=? WHERE id=?",
                      (dialog.title, dialog.username, enc_pw, dialog.link, dialog.notes, dialog.category, selected_id))
            conn.commit()
            self.load_data()
        conn.close()

    def delete_entry(self):
        selected_id = self.tree.focus()
        if not selected_id: return
        if messagebox.askyesno("Delete", "Are you sure you want to delete this entry?"):
            conn = self.get_db_connection()
            c = conn.cursor()
            c.execute("DELETE FROM passwords WHERE id=?", (selected_id,))
            conn.commit()
            conn.close()
            self.load_data()

class EntryWindow:
    def __init__(self, master, window_title, title="", username="", password="", link="", notes="", category="General"):
        self.top = tk.Toplevel(master)
        self.top.title(window_title)
        self.top.geometry("650x500")
        self.top.wait_visibility()
        self.top.grab_set()

        self.top.transient(master)
        self.top.after(10, self.top.grab_set)

        self.saved = False
        
        main_frame = tk.Frame(self.top, padx=20, pady=20)
        main_frame.pack(fill=tk.BOTH, expand=True)

        fields = [("Category", category), ("Title", title), ("Username", username), 
                 ("Password", password), ("Link", link), ("Notes", notes)]
        
        self.entries = {}
        self.password_visible_var = tk.BooleanVar(value=False)
        
        for i, (label, val) in enumerate(fields):
            tk.Label(main_frame, text=label + ":", font=("Arial", 10, "bold")).grid(row=i, column=0, padx=10, pady=8, sticky="e")
            if label == "Category":
                ent = ttk.Combobox(main_frame, width=38, values=["General", "Email", "Social Media", "Work", "Banking", "Webshop", "Other"])
                ent.set(val)
            elif label == "Notes":
                ent = tk.Text(main_frame, width=40, height=4, font=("Arial", 10))
                ent.insert("1.0", val)
            else:
                ent = tk.Entry(main_frame, width=40, font=("Arial", 10))
                if label == "Password": ent.config(show="*")
                ent.insert(0, val)
            ent.grid(row=i, column=1, padx=10, pady=8, sticky="w")
            self.entries[label] = ent
            
            if label == "Password":
                tk.Checkbutton(main_frame, text="👁", variable=self.password_visible_var, command=self.toggle_password).grid(row=i, column=2)
                tk.Button(main_frame, text="🎲", command=self.generate, width=3).grid(row=i, column=3)

        btn_f = tk.Frame(main_frame)
        btn_f.grid(row=7, column=0, columnspan=4, pady=20)
        tk.Button(btn_f, text="💾 Save", command=self.save, bg="#4CAF50", fg="white", width=12).pack(side=tk.LEFT, padx=10)
        tk.Button(btn_f, text="❌ Cancel", command=self.top.destroy, bg="#f44336", fg="white", width=12).pack(side=tk.LEFT, padx=10)

    def toggle_password(self):
        self.entries["Password"].config(show="" if self.password_visible_var.get() else "*")

    def generate(self):
        new_pw = generate_password(16)
        self.entries["Password"].delete(0, tk.END)
        self.entries["Password"].insert(0, new_pw)

    def save(self):
        self.category = self.entries["Category"].get()
        self.title = self.entries["Title"].get().strip()
        self.username = self.entries["Username"].get().strip()
        self.password = self.entries["Password"].get()
        self.link = self.entries["Link"].get().strip()
        self.notes = self.entries["Notes"].get("1.0", tk.END).strip()
        
        if self.title and self.password:
            self.saved = True
            self.top.destroy()
        else:
            messagebox.showerror("Error", "Title and Password are required!")

def setup_master_password():
    root = tk.Tk()
    root.withdraw()
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute("SELECT master_hash FROM settings WHERE id=1")
    res = c.fetchone()
    if not res or not res[0]:
        pw = simpledialog.askstring("Master Password", "Create a new master password (min 4 chars):", show='*')
        if pw and len(pw) >= 4:
            c.execute("UPDATE settings SET master_hash=? WHERE id=1", (hash_password(pw),))
            conn.commit()
        else:
            conn.close(); root.destroy(); return None
    conn.close(); root.destroy(); return True

def main():
    init_db()
    if not setup_master_password(): return
    
    root = tk.Tk()
    root.withdraw()
    
    master_pw = simpledialog.askstring("Login", "Master Password:", show='*')
    if not master_pw: return

    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute("SELECT master_hash, salt FROM settings WHERE id=1")
    stored_hash, salt = c.fetchone()
    conn.close()

    if hash_password(master_pw) == stored_hash:
        key = generate_key(master_pw, salt)
        cipher_suite = Fernet(key)
        root.deiconify()
        app = PasswordManagerApp(root, cipher_suite)
        root.mainloop()
    else:
        messagebox.showerror("Error", "Incorrect master password!")
        root.destroy()

if __name__ == "__main__":
    main()
