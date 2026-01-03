# 🔐 PasswordBox – Installation Guide

## 📋 System Requirements
* **Operating System**: 
    * Linux (Ubuntu, Linux Mint, Debian – Recommended)
    * Windows 10 / 11
* **Python**: Version 3.9 or newer
* **GUI Support**: Graphical environment (required for Tkinter)

---

## 🐍 1. Checking Python
Run the following command in your terminal:
`python3 --version`

**If not installed:**
* **Ubuntu / Debian / Mint**: 
    ```bash
    sudo apt update
    sudo apt install python3 python3-pip python3-tk
    ```
* **Windows**: 
    * Download from [python.org](https://www.python.org).
    * **Crucial**: Check the **"Add Python to PATH"** box during installation.

---

## 📦 2. Installing Required Packages
Run this in your Terminal or Command Prompt:
`pip install cryptography pyperclip`

**For Linux Users (Very Important):**
To ensure the clipboard functions correctly, install `xclip`:
`sudo apt install xclip`

---

## 📁 3. Program Files
Place the following file into a dedicated folder:
* `PasswordBox.py`

**Automatic File Generation:**
Upon the first launch, the program will automatically create:
* `PasswordBox.db`

> ⚠️ **Warning:** Do not delete this database file! It contains all your encrypted passwords.

---

## ▶️ 4. Launching the Program
* **Linux**: `python3 PasswordBox.py`
* **Windows**: `python PasswordBox.py`

---

## 🔑 5. First Launch – Master Password
On the first run, the program will prompt you to set a **Master Password**.
* **Requirement**: Minimum 8 characters.
* **Purpose**: This password protects all your stored credentials.
* ⚠️ **Caution**: If you forget this password, your data **cannot** be recovered!

---

## 🧪 6. Quick Start Guide
* **➕ Add**: Create a new password entry.
* **🔍 Search**: Filter by name or category.
* **👁 Show**: Reveal passwords directly in the table.
* **🔑 Copy**: Copy the password to your clipboard.
* **⏱️ Auto-Clear**: The clipboard is automatically wiped after 30 seconds for security.

---

## 🔐 Security Recommendations
* **File Privacy**: Never share your `PasswordBox.db` file.
* **Permissions (Linux)**: Set recommended file permissions:
    `chmod 600 PasswordBox.db`
* **Safety**: 
    * Do **not** run the program with administrator/root privileges.
    * Do **not** leave the application open and unattended.

---

## ❗ Troubleshooting
**Clipboard/Paste not working on Linux?**
Check if `xclip` is installed:
`which xclip`
If no path is returned, install it:
`sudo apt install xclip`

---

## 🧹 Uninstallation
To remove the software, simply delete:
1. `PasswordBox.py`
2. `PasswordBox.db`

⚠️ **Warning**: This will permanently delete all your stored passwords.

---

## 📌 Technical Note
**PasswordBox Pro is designed with privacy in mind:**
* **Offline**: Works entirely without an internet connection.
* **No Data Sharing**: It does not send data to any external server.
* **No Cloud**: Your data is stored strictly locally using strong encryption.


------------------------------------------------------------------------



# 🔐 PasswordBox – Telepítési útmutató

## 📋 Rendszerkövetelmények
* **Operációs rendszer**: 
    * Linux (Ubuntu, Linux Mint, Debian – ajánlott)
    * Windows 10 / 11
* **Python**: 3.9 vagy újabb verzió
* **Grafikus környezet**: Szükséges a Tkinter könyvtár használatához

---

## 🐍 1. Python ellenőrzése
Futtasd a következő parancsot a terminálban:
`python3 --version`

**Ha nincs telepítve:**
* **Ubuntu / Debian / Mint**: 
    ```bash
    sudo apt update
    sudo apt install python3 python3-pip python3-tk
    ```
* **Windows**: 
    * Töltsd le a [python.org](https://www.python.org) oldalról.
    * **Fontos**: Telepítéskor pipáld be az **"Add Python to PATH"** opciót.

---

## 📦 2. Szükséges csomagok telepítése
Futtasd ezt a terminálban vagy parancssorban:
`pip install cryptography pyperclip`

**Linux felhasználóknak (Nagyon fontos):**
A vágólap megfelelő működéséhez telepítsd az `xclip` csomagot:
`sudo apt install xclip`

---

## 📁 3. Programfájlok
Másold a következő fájlt egy külön mappába:
* `PasswordBox.py`

**Automatikus fájllétrehozás:**
Az első indításkor a program automatikusan létrehozza a következőt:
* `PasswordBox_Pro.db`

> ⚠️ **Figyelem:** Ne töröld ezt az adatbázisfájlt! Ez tartalmazza az összes titkosított jelszavadat.

---

## ▶️ 4. A program indítása
* **Linux**: `python3 PasswordBox.py`
* **Windows**: `python PasswordBox.py`

---

## 🔑 5. Első indítás – Mesterjelszó
Az első futtatáskor a program egy **Mesterjelszó** megadását kéri.
* **Elvárás**: Minimum 8 karakter.
* **Cél**: Ez a jelszó védi az összes tárolt adatodat.
* ⚠️ **Vigyázat**: Ha elfelejted ezt a jelszót, az adataid **nem** állíthatók helyre!

---

## 🧪 6. Gyors használati útmutató
* **➕ Hozzáadás**: Új jelszóbejegyzés létrehozása.
* **🔍 Keresés**: Szűrés név vagy kategória alapján.
* **👁 Megjelenítés**: Jelszavak láthatóvá tétele a táblázatban.
* **🔑 Másolás**: Jelszó másolása a vágólapra.
* **⏱️ Automatikus törlés**: A vágólap tartalma biztonsági okokból 30 másodperc után törlődik.

---

## 🔐 Biztonsági ajánlások
* **Adatvédelem**: Soha ne oszd meg a `PasswordBox.db` fájlt másokkal.
* **Jogosultságok (Linux)**: Javasolt fájljogosultság beállítása:
    `chmod 600 PasswordBox.db`
* **Biztonság**: 
    * **Ne** futtasd a programot rendszergazdai (root) jogokkal.
    * **Ne** hagyd az alkalmazást nyitva és felügyelet nélkül.

---

## ❗ Hibaelhárítás
**Nem működik a beillesztés Linuxon?**
Ellenőrizd, hogy az `xclip` telepítve van-e:
`which xclip`
Ha nem kapsz elérési utat, telepítsd:
`sudo apt install xclip`

---

## 🧹 Eltávolítás
A szoftver eltávolításához egyszerűen töröld a következőket:
1. `PasswordBox.py`
2. `PasswordBox.db`

⚠️ **Figyelem**: Ez véglegesen törli az összes tárolt jelszavadat.

---

## 📌 Technikai megjegyzés
**A PasswordBox Pro a privát szférát szem előtt tartva készült:**
* **Offline**: Teljesen internetkapcsolat nélkül működik.
* **Nincs adatmegosztás**: Nem küld adatokat semmilyen külső szerverre.
* **Nincs felhő**: Az adataid kizárólag helyben, erős titkosítással vannak tárolva.

