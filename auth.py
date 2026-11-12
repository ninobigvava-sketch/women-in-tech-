"""User registration and login."""
from getpass import getpass

from cryptography.exceptions import InvalidTag

from config import KEY_SIZE
from key_management import create_user_record, unlock_master_key
from storage import (
    get_user_vault,
    load_users,
    normalize_username,
    save_users,
    validate_username,
)


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
