mport base64
import json
import os
import re
import struct
import uuid
from getpass import getpass
from pathlib import Path, PureWindowsPath
from tempfile import NamedTemporaryFile

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


# Project paths and cryptographic configuration
BASE_DIR = Path(__file__).resolve().parent
USERS_FILE = BASE_DIR / "users.json"
VAULT_DIR = BASE_DIR / "vault_data"
RESTORED_DIR = BASE_DIR / "restored_files"

KDF_NAME = "PBKDF2-HMAC-SHA256"
PBKDF2_ITERATIONS = 600_000
SALT_SIZE = 16
KEY_SIZE = 32
NONCE_SIZE = 12
MAGIC_HEADER = b"EFV1"

USERNAME_PATTERN = re.compile(r"^[A-Za-z0-9_.-]{3,32}$")


# -------------------- General helpers --------------------

def encode_b64(data):
    return base64.b64encode(data).decode("ascii")


def decode_b64(value):
    return base64.b64decode(value.encode("ascii"), validate=True)


def set_private_permissions(path):
    """Best-effort restrictive permissions on POSIX systems."""
    try:
        if os.name == "posix":
            path = Path(path)
            os.chmod(path, 0o700 if path.is_dir() else 0o600)
    except OSError:
        pass


        ef atomic_write_json(path, data):
    """Write JSON safely through a temporary file and atomic replacement."""
    temporary_path = None
    try:
        with NamedTemporaryFile(
            mode="w", encoding="utf-8", dir=path.parent, delete=False
        ) as temp_file:
            json.dump(data, temp_file, indent=4)
            temp_file.write("\n")
            temp_file.flush()
            os.fsync(temp_file.fileno())
            temporary_path = Path(temp_file.name)

             set_private_permissions(temporary_path)
        os.replace(temporary_path, path)
        set_private_permissions(path)
    finally:
        if temporary_path is not None and temporary_path.exists():
            temporary_path.unlink(missing_ok=True)


def initialize_project():
    VAULT_DIR.mkdir(parents=True, exist_ok=True)
    RESTORED_DIR.mkdir(parents=True, exist_ok=True)
    set_private_permissions(VAULT_DIR)
    set_private_permissions(RESTORED_DIR)

    if not USERS_FILE.exists():
        atomic_write_json(USERS_FILE, {})

    print("Encrypted File Vault initialized successfully.")


def load_users():
    try:
        with open(USERS_FILE, "r", encoding="utf-8") as file:
            users = json.load(file)
        if not isinstance(users, dict):
            raise ValueError("Invalid users database format.")
        return users
    except json.JSONDecodeError as error:
        raise RuntimeError("The users database is damaged.") from error


def save_users(users):
    atomic_write_json(USERS_FILE, users)


    def normalize_username(username):
    return username.strip().lower()


def validate_username(username):
    return bool(USERNAME_PATTERN.fullmatch(username)) and username not in {".", ".."}


def get_user_vault(username):
    if not validate_username(username):
        raise ValueError("Invalid username.")
    folder = VAULT_DIR / username
    folder.mkdir(parents=True, exist_ok=True)
    set_private_permissions(folder)
    return folder


# -------------------- Key derivation --------------------

def derive_wrapping_key(password, salt):
    """Derive a 256-bit wrapping key from the user's password."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_SIZE,
        salt=salt,
        iterations=PBKDF2_ITERATIONS
    )
    return kdf.derive(password.encode("utf-8"))


    def create_user_record(username, password):
    """Create a random Master Key and encrypt it with the wrapping key."""
    salt = os.urandom(SALT_SIZE)
    wrapping_key = derive_wrapping_key(password, salt)

    master_key = AESGCM.generate_key(bit_length=256)
    wrap_nonce = os.urandom(NONCE_SIZE)

    encrypted_master_key = AESGCM(wrapping_key).encrypt(
        wrap_nonce,
        master_key,
        username.encode("utf-8")
    )

    return {
        "kdf": KDF_NAME,
        "kdf_iterations": PBKDF2_ITERATIONS,
        "salt": encode_b64(salt),
        "wrap_nonce": encode_b64(wrap_nonce),
        "encrypted_master_key": encode_b64(encrypted_master_key)
    }


def unlock_master_key(username, password, record):
    """Recover the Master Key after verifying the password."""
    if record.get("kdf") != KDF_NAME:
        raise ValueError("Unsupported KDF.")
    if record.get("kdf_iterations") != PBKDF2_ITERATIONS:
        raise ValueError("Unsupported KDF parameters.")

    salt = decode_b64(record["salt"])
    nonce = decode_b64(record["wrap_nonce"])
    encrypted_master_key = decode_b64(record["encrypted_master_key"])

    if len(salt) != SALT_SIZE or len(nonce) != NONCE_SIZE:
        raise ValueError("Invalid account cryptographic metadata.")

        wrapping_key = derive_wrapping_key(password, salt)

    return AESGCM(wrapping_key).decrypt(
        nonce,
        encrypted_master_key,
        username.encode("utf-8")
    )


# -------------------- Registration and login --------------------

def register_user():
    print("\n=== User Registration ===")
    username = normalize_username(input("Choose a username: "))

    if not validate_username(username):
        print("Use 3-32 characters: letters, numbers, underscore, dot or hyphen.")
        return

    users = load_users()
    if username in users:
        print("This username is already registered.")
        return

    password = getpass("Create a password (minimum 12 characters): ")
    if len(password) < 12:
        print("Password must contain at least 12 characters.")
        return

    confirmation = getpass("Confirm your password: ")
    if password != confirmation:
        print("Passwords do not match.")
        return

    users[username] = create_user_record(username, password)
    save_users(users)
    get_user_vault(username)
    print("Registration completed successfully.")
    print("Your Master Key has been created and protected.")


def login_user():
    print("\n=== User Login ===")
    username = normalize_username(input("Username: "))

    if not validate_username(username):
        print("Invalid username or password.")
        return None

    users = load_users()
    record = users.get(username)
    if record is None:
        print("Invalid username or password.")
        return None

    password = getpass("Password: ")

    try:
        master_key = unlock_master_key(username, password, record)
        if len(master_key) != KEY_SIZE:
            raise ValueError("Invalid Master Key size.")
        get_user_vault(username)
        print("Login successful.")
        return username, master_key
    except (InvalidTag, KeyError, ValueError, TypeError):
        print("Invalid username or password, or damaged account data.")
        return None



        # -------------------- Vault file format --------------------

def make_payload(filename, file_content):
    """Put filename length, filename and file bytes into one payload."""
    filename_bytes = filename.encode("utf-8")
    if not filename_bytes or len(filename_bytes) > 65535:
        raise ValueError("Invalid filename length.")
    return struct.pack(">I", len(filename_bytes)) + filename_bytes + file_content


def parse_payload(payload):
    if len(payload) < 4:
        raise ValueError("Incomplete decrypted data.")

    name_length = struct.unpack(">I", payload[:4])[0]
    if name_length == 0 or len(payload) < 4 + name_length:
        raise ValueError("Invalid encrypted filename.")

    filename = payload[4:4 + name_length].decode("utf-8")
    content = payload[4 + name_length:]

    if (
        Path(filename).name != filename
        or PureWindowsPath(filename).name != filename
        or filename in {"", ".", ".."}
    ):
        raise ValueError("Unsafe filename in encrypted data.")

    return filename, content


    def encrypt_file(username, master_key):
    print("\n=== Encrypt a File ===")
    entered_path = input("Enter the full path of the file: ").strip().strip('"')
    source = Path(entered_path).expanduser()

    if not source.exists() or not source.is_file():
        print("The selected file does not exist.")
        return

    try:
        source = source.resolve()
        vault_folder = get_user_vault(username)

        if source.is_relative_to(vault_folder.resolve()):
            print("Choose a file outside your Vault folder.")
            return

        original_data = source.read_bytes()
        plaintext = make_payload(source.name, original_data)

        nonce = os.urandom(NONCE_SIZE)
        aad = MAGIC_HEADER + username.encode("utf-8")
        ciphertext = AESGCM(master_key).encrypt(nonce, plaintext, aad)

        file_id = uuid.uuid4().hex
        vault_path = vault_folder / f"{file_id}.vault"
        vault_path.write_bytes(MAGIC_HEADER + nonce + ciphertext)
        set_private_permissions(vault_path)

        print("File encrypted successfully.")
        print(f"Vault file ID: {file_id}")
        print("The original file has not been deleted.")

    except (OSError, ValueError, UnicodeError) as error:
        print(f"Could not encrypt the file: {error}")


def get_vault_file(username, file_id):
    if not re.fullmatch(r"[a-f0-9]{32}", file_id):
        raise ValueError("Invalid file ID.")

    path = get_user_vault(username) / f"{file_id}.vault"
    if not path.is_file():
        raise FileNotFoundError("Vault file not found.")
    return path


def unique_output_path(folder, filename):
    target = folder / filename
    if not target.exists():
        return target

    original = Path(filename)
    number = 1
    while True:
        candidate = folder / f"{original.stem}_{number}{original.suffix}"
        if not candidate.exists():
            return candidate
            number += 1


def decrypt_file(username, master_key):
    print("\n=== Decrypt a File ===")
    file_id = input("Enter the Vault file ID: ").strip()

    try:
        vault_path = get_vault_file(username, file_id)
        encrypted_data = vault_path.read_bytes()

        if len(encrypted_data) < 4 + NONCE_SIZE + 16:
            raise ValueError("Vault file is incomplete.")
        if encrypted_data[:4] != MAGIC_HEADER:
            raise ValueError("Unknown Vault file format.")

        nonce = encrypted_data[4:4 + NONCE_SIZE]
        ciphertext = encrypted_data[4 + NONCE_SIZE:]
        aad = MAGIC_HEADER + username.encode("utf-8")

        plaintext = AESGCM(master_key).decrypt(nonce, ciphertext, aad)
        filename, file_content = parse_payload(plaintext)

        restore_folder = RESTORED_DIR / username
        restore_folder.mkdir(parents=True, exist_ok=True)
        output_path = unique_output_path(restore_folder, filename)
        output_path.write_bytes(file_content)
        set_private_permissions(output_path)

        print("File decrypted successfully.")
        print(f"Restored file: {output_path}")

    except InvalidTag:
        print("Decryption failed: wrong key or modified encrypted file.")
    except (OSError, ValueError, FileNotFoundError, UnicodeError) as error:
        print(f"Could not decrypt the file: {error}")


# -------------------- List and delete --------------------
def list_files(username):
    print("\n=== Your Encrypted Files ===")
    files = sorted(get_user_vault(username).glob("*.vault"))

    if not files:
        print("Your Vault is empty.")
        return

    print(f"{'FILE ID':<34} {'SIZE (BYTES)':>14}")
    print("-" * 50)
    for item in files:
        print(f"{item.stem:<34} {item.stat().st_size:>14}")


def delete_file(username):
    print("\n=== Delete an Encrypted File ===")
    file_id = input("Enter the Vault file ID: ").strip()

    try:
        path = get_vault_file(username, file_id)
        confirmation = input(
            f"Delete {path.name}? Type YES to confirm: "
        ).strip()

        if confirmation != "YES":
            print("Deletion cancelled.")
            return

        path.unlink()
        print("Encrypted file deleted from the Vault.")
        print("Normal deletion does not guarantee secure erasure from SSDs.")
    except (OSError, ValueError, FileNotFoundError) as error:
        print(f"Could not delete the file: {error}")



# -------------------- Logged-in user menu --------------------

def main_menu(username, master_key):
    while True:
        print("\n" + "=" * 45)
        print(f"ENCRYPTED FILE VAULT — USER: {username}")
        print("=" * 45)
        print("1. Encrypt a file")
        print("2. Decrypt a file")
        print("3. List encrypted files")
        print("4. Delete an encrypted file")
        print("5. Log out")

        choice = input("Choose an option: ").strip()

        if choice == "1":
            encrypt_file(username, master_key)
        elif choice == "2":
            decrypt_file(username, master_key)
        elif choice == "3":
            list_files(username)
        elif choice == "4":
            delete_file(username)
        elif choice == "5":
            print("You have been logged out.")
            break
        else:
            print("Invalid option. Please choose 1-5.")


# -------------------- Main application --------------------

def main():
    initialize_project()

    while True:
        print("\n" + "=" * 35)
        print("WELCOME TO ENCRYPTED FILE VAULT")
        print("=" * 35)
        print("1. Register")
        print("2. Login")
        print("3. Exit")

        choice = input("Choose an option: ").strip()

        try:
            if choice == "1":
                register_user()
            elif choice == "2":
                result = login_user()
                if result is not None:
                    username, master_key = result
                    main_menu(username, master_key)
            elif choice == "3":
                print("Thank you for using Encrypted File Vault.")
                break
            else:
                print("Invalid option. Please choose 1-3.")
        except (OSError, RuntimeError, ValueError) as error:
            print(f"Application error: {error}")


if __name__ == "__main__":
    main()
