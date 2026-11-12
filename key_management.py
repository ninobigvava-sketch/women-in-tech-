"""Key derivation and Master Key wrapping/unwrapping."""
import os

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from config import KDF_NAME, KEY_SIZE, NONCE_SIZE, PBKDF2_ITERATIONS, SALT_SIZE
from utils import decode_b64, encode_b64


def derive_wrapping_key(password, salt):
    """Derive a 256-bit wrapping key from the user's password."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_SIZE,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
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
        username.encode("utf-8"),
    )

    return {
        "kdf": KDF_NAME,
        "kdf_iterations": PBKDF2_ITERATIONS,
        "salt": encode_b64(salt),
        "wrap_nonce": encode_b64(wrap_nonce),
        "encrypted_master_key": encode_b64(encrypted_master_key),
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
        username.encode("utf-8"),
    )
