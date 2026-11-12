"""Project paths and cryptographic configuration."""
import re
from pathlib import Path

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
