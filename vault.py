"""Vault file format and file operations (encrypt, decrypt, list, delete)."""
import os
import re
import struct
import uuid
from pathlib import Path, PureWindowsPath

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from config import MAGIC_HEADER, NONCE_SIZE, RESTORED_DIR
from storage import get_user_vault
from utils import set_private_permissions


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


# -------------------- Encrypt --------------------

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


# -------------------- Decrypt --------------------

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
