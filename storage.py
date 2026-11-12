"""Project initialization, users database and per-user vault folders."""
import json

from config import RESTORED_DIR, USERS_FILE, USERNAME_PATTERN, VAULT_DIR
from utils import atomic_write_json, set_private_permissions


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
