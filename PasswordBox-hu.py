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

# --- Titkosítási segédfunkciók ---
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
    c.execute('''CREATE TABLE IF NOT EXISTS jelszavak (
                    id INTEGER PRIMARY KEY,
                    megnevezes TEXT,
                    felhasznalonev TEXT,
                    jelszo BLOB,
                    link TEXT,
                    megjegyzes TEXT,
                    kategoria TEXT
                )''')
    
    c.execute("SELECT salt FROM settings WHERE id = 1")
    if not c.fetchone():
        salt = os.urandom(16)
        c.execute("INSERT INTO settings (id, salt, master_hash) VALUES (1, ?, ?)", 
                  (salt, None))
    
    conn.commit()
    conn.close()

def generaljelszo(hossz=16):
    kisbetu = string.ascii_lowercase
    nagybetu = string.ascii_uppercase
    szamok = string.digits
    specialis = "!@#$%&*+?="
    
    jelszo = [
        random.choice(nagybetu),
        random.choice(kisbetu),
        random.choice(szamok),
        random.choice(specialis)
    ]
    
    osszes = kisbetu + nagybetu + szamok + specialis
    jelszo += random.choices(osszes, k=hossz-4)
    random.shuffle(jelszo)
    return ''.join(jelszo)

class JelszoKezeloApp:
    def __init__(self, root, cipher_suite):
        self.root = root
        self.cipher_suite = cipher_suite
        self.root.title("PasswordBox")
        self.root.geometry("1200x650")
        self.root.minsize(900, 500)

        self.kereso_var = tk.StringVar()
        self.jelszo_lathato = tk.BooleanVar(value=False)
        self.kereso_var.trace("w", lambda *args: self.betoltes())

        # UI Felépítése
        main_frame = tk.Frame(root, bg="white")
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        top_frame = tk.Frame(main_frame, bg="white")
        top_frame.pack(fill=tk.X, pady=(0, 10))
        
        tk.Label(top_frame, text="🔍 Keresés:", font=("Arial", 10, "bold"), bg="white").pack(side=tk.LEFT, padx=5)
        kereso_entry = tk.Entry(top_frame, textvariable=self.kereso_var, width=50, font=("Arial", 10))
        kereso_entry.pack(side=tk.LEFT, padx=5)

        tree_frame = tk.Frame(main_frame)
        tree_frame.pack(fill=tk.BOTH, expand=True)

        self.tree = ttk.Treeview(
            tree_frame, 
            columns=("Megnevezés", "Felhasználónév", "Jelszó", "Kategória", "Link", "Megjegyzés"), 
            show="headings",
            selectmode="browse"
        )
        
        oszlop_szelessegek = {
            "Megnevezés": 150, "Felhasználónév": 140, "Jelszó": 150,
            "Kategória": 120, "Link": 180, "Megjegyzés": 180
        }
        
        for col in self.tree["columns"]:
            self.tree.heading(col, text=col)
            self.tree.column(col, width=oszlop_szelessegek[col])

        scrollbar = ttk.Scrollbar(tree_frame, orient=tk.VERTICAL, command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar.set)
        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        self.tree.bind("<Double-1>", lambda e: self.szerkesztes())

        btn_frame = tk.Frame(main_frame, bg="white")
        btn_frame.pack(pady=15)
        tk.Checkbutton(
            top_frame,
            text="👁 Jelszó megjelenítése",
            variable=self.jelszo_lathato,
            command=self.betoltes,
            bg="white",
            font=("Arial", 9, "bold")
        ).pack(side=tk.RIGHT, padx=10)

        buttons = [
            ("➕ Hozzáadás", self.hozzaadas, "#4CAF50"),
            ("✏️ Szerkesztés", self.szerkesztes, "#2196F3"),
            ("🗑️ Törlés", self.torles, "#f44336"),
            ("🔑 Jelszó Másolása", lambda: self.masolas("password"), "#FF9800"),
            ("👤 Felhasználó Másolása", lambda: self.masolas("username"), "#9C27B0")
        ]

        for text, cmd, color in buttons:
            tk.Button(btn_frame, text=text, command=cmd, width=18, bg=color, fg="white",
                      font=("Arial", 9, "bold"), cursor="hand2", relief=tk.RAISED).pack(side=tk.LEFT, padx=5)

        status_frame = tk.Frame(root, bg="#f0f0f0")
        status_frame.pack(side=tk.BOTTOM, fill=tk.X)
        
        self.status_label = tk.Label(status_frame, text="Betöltés...", font=("Arial", 9), fg="gray", bg="#f0f0f0")
        self.status_label.pack(pady=5)

        self.betoltes()

    def get_db_connection(self):
        return sqlite3.connect(DB_NAME)

    def betoltes(self):
        for row in self.tree.get_children():
            self.tree.delete(row)
        
        keresett = f"%{self.kereso_var.get().lower()}%"
        conn = self.get_db_connection()
        c = conn.cursor()
        c.execute("""SELECT id, megnevezes, felhasznalonev, jelszo, kategoria, link, megjegyzes 
                     FROM jelszavak WHERE LOWER(megnevezes) LIKE ? OR LOWER(kategoria) LIKE ? OR LOWER(felhasznalonev) LIKE ?
                     ORDER BY megnevezes""", (keresett, keresett, keresett))
        
        count = 0
        for sor in c.fetchall():
            try:
                dec_pw = self.cipher_suite.decrypt(sor[3]).decode()

                if self.jelszo_lathato.get():
                    password_display = dec_pw
                else:
                    password_display = "••••••••"
            except:
                password_display = "❌ Hiba"
            
            self.tree.insert("", tk.END, iid=sor[0], values=(sor[1], sor[2], password_display, sor[4], sor[5], sor[6]))
            count += 1
        
        conn.close()
        self.status_label.config(text=f"Védett mód | Bejegyzések: {count}", fg="gray")

    def masolas(self, tipus):
        kivalasztott_id = self.tree.focus()
        if not kivalasztott_id:
            return messagebox.showwarning("Figyelmeztetés", "Válassz ki egy elemet!")

        try:
            with self.get_db_connection() as conn:
                c = conn.cursor()
                if tipus == "password":
                    c.execute("SELECT jelszo FROM jelszavak WHERE id=?", (kivalasztott_id,))
                    ertek = self.cipher_suite.decrypt(c.fetchone()[0]).decode()
                    szoveg = "Jelszó"
                else:
                    c.execute("SELECT felhasznalonev FROM jelszavak WHERE id=?", (kivalasztott_id,))
                    ertek = c.fetchone()[0]
                    szoveg = "Felhasználónév"

            if ertek:
                pyperclip.copy(ertek)
                self.status_label.config(
                    text=f"✅ {szoveg} másolva (30 mp múlva törlődik)",
                    fg="#2E7D32"
                )

                # ✅ BIZTONSÁGOS IDŐZÍTÉS
                self.root.after(30000, self.clear_clipboard)

        except Exception as e:
            messagebox.showerror("Hiba", str(e))


    def clear_clipboard(self):
        try:
            pyperclip.copy("")
            self.status_label.config(
                text="ℹ️ Vágólap ürítve biztonsági okokból.",
                fg="gray"
            )
        except:
            pass


    def hozzaadas(self):
        uj = JelszoAblak(self.root, "Új bejegyzés")
        self.root.wait_window(uj.top)
        if uj.mentett:
            try:
                enc_password = self.cipher_suite.encrypt(uj.jelszo.encode())
                conn = self.get_db_connection()
                c = conn.cursor()
                c.execute("INSERT INTO jelszavak (megnevezes, felhasznalonev, jelszo, link, megjegyzes, kategoria) VALUES (?,?,?,?,?,?)",
                          (uj.megnevezes, uj.felhasznalonev, enc_password, uj.link, uj.megjegyzes, uj.kategoria))
                conn.commit()
                conn.close()
                self.betoltes()
            except Exception as e:
                messagebox.showerror("Hiba", str(e))

    def szerkesztes(self):
        kivalasztott_id = self.tree.focus()
        if not kivalasztott_id: return
        conn = self.get_db_connection()
        c = conn.cursor()
        c.execute("SELECT megnevezes, felhasznalonev, jelszo, link, megjegyzes, kategoria FROM jelszavak WHERE id=?", (kivalasztott_id,))
        adat = list(c.fetchone())
        adat[2] = self.cipher_suite.decrypt(adat[2]).decode()
        szerk = JelszoAblak(self.root, "Szerkesztés", *adat)
        self.root.wait_window(szerk.top)
        if szerk.mentett:
            enc_pw = self.cipher_suite.encrypt(szerk.jelszo.encode())
            c.execute("UPDATE jelszavak SET megnevezes=?, felhasznalonev=?, jelszo=?, link=?, megjegyzes=?, kategoria=? WHERE id=?",
                      (szerk.megnevezes, szerk.felhasznalonev, enc_pw, szerk.link, szerk.megjegyzes, szerk.kategoria, kivalasztott_id))
            conn.commit()
            self.betoltes()
        conn.close()

    def torles(self):
        kivalasztott_id = self.tree.focus()
        if not kivalasztott_id: return
        if messagebox.askyesno("Törlés", "Biztosan törlöd?"):
            conn = self.get_db_connection()
            c = conn.cursor()
            c.execute("DELETE FROM jelszavak WHERE id=?", (kivalasztott_id,))
            conn.commit()
            conn.close()
            self.betoltes()

class JelszoAblak:
    def __init__(self, master, cim, megnevezes="", felhasznalonev="", jelszo="", link="", megjegyzes="", kategoria="Általános"):
        self.top = tk.Toplevel(master)
        self.top.title(cim)
        self.top.geometry("650x500")
        self.top.wait_visibility()
        self.top.grab_set()

        self.top.transient(master)
        self.top.after(10, self.top.grab_set)

        self.mentett = False

        
        main_frame = tk.Frame(self.top, padx=20, pady=20)
        main_frame.pack(fill=tk.BOTH, expand=True)

        mezok = [("Kategória", kategoria), ("Megnevezés", megnevezes), ("Felhasználónév", felhasznalonev), 
                 ("Jelszó", jelszo), ("Link", link), ("Megjegyzés", megjegyzes)]
        
        self.entrys = {}
        self.jelszo_lathatosag = tk.BooleanVar(value=False)
        
        for i, (label, val) in enumerate(mezok):
            tk.Label(main_frame, text=label + ":", font=("Arial", 10, "bold")).grid(row=i, column=0, padx=10, pady=8, sticky="e")
            if label == "Kategória":
                ent = ttk.Combobox(main_frame, width=38, values=["Általános", "Email", "Közösségi média", "Munka", "Bank", "Webshop", "Egyéb"])
                ent.set(val)
            elif label == "Megjegyzés":
                ent = tk.Text(main_frame, width=40, height=4, font=("Arial", 10))
                ent.insert("1.0", val)
            else:
                ent = tk.Entry(main_frame, width=40, font=("Arial", 10))
                if label == "Jelszó": ent.config(show="*")
                ent.insert(0, val)
            ent.grid(row=i, column=1, padx=10, pady=8, sticky="w")
            self.entrys[label] = ent
            
            if label == "Jelszó":
                tk.Checkbutton(main_frame, text="👁", variable=self.jelszo_lathatosag, command=self.toggle_jelszo).grid(row=i, column=2)
                tk.Button(main_frame, text="🎲", command=self.gen, width=3).grid(row=i, column=3)

        btn_f = tk.Frame(main_frame)
        btn_f.grid(row=7, column=0, columnspan=4, pady=20)
        tk.Button(btn_f, text="💾 Mentés", command=self.mentes, bg="#4CAF50", fg="white", width=12).pack(side=tk.LEFT, padx=10)
        tk.Button(btn_f, text="❌ Mégse", command=self.top.destroy, bg="#f44336", fg="white", width=12).pack(side=tk.LEFT, padx=10)

    def toggle_jelszo(self):
        self.entrys["Jelszó"].config(show="" if self.jelszo_lathatosag.get() else "*")

    def gen(self):
        uj = generaljelszo(16)
        self.entrys["Jelszó"].delete(0, tk.END)
        self.entrys["Jelszó"].insert(0, uj)

    def mentes(self):
        self.kategoria = self.entrys["Kategória"].get()
        self.megnevezes = self.entrys["Megnevezés"].get().strip()
        self.felhasznalonev = self.entrys["Felhasználónév"].get().strip()
        self.jelszo = self.entrys["Jelszó"].get()
        self.link = self.entrys["Link"].get().strip()
        self.megjegyzes = self.entrys["Megjegyzés"].get("1.0", tk.END).strip()
        if self.megnevezes and self.jelszo:
            self.mentett = True
            self.top.destroy()
        else:
            messagebox.showerror("Hiba", "Név és jelszó kötelező!")

def setup_master_password():
    root = tk.Tk()
    root.withdraw()
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute("SELECT master_hash FROM settings WHERE id=1")
    res = c.fetchone()
    if not res or not res[0]:
        pw = simpledialog.askstring("Mesterjelszó", "Adj meg egy új mesterjelszót (min 4 kar):", show='*')
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
    
    master_pw = simpledialog.askstring("Belépés", "Mesterjelszó:", show='*')
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
        app = JelszoKezeloApp(root, cipher_suite)
        root.mainloop()
    else:
        messagebox.showerror("Hiba", "Hibás mesterjelszó!")
        root.destroy()

if __name__ == "__main__":
    main()
