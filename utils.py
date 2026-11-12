"""General helper functions."""
import base64
import json
import os
from pathlib import Path
from tempfile import NamedTemporaryFile


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


def atomic_write_json(path, data):
    """Write JSON safely through a temporary file and atomic replacement."""
    path = Path(path)
    temporary_path = None
    try:
        with NamedTemporaryFile(
            mode="w", encoding="utf-8", dir=path.parent, delete=False
        ) as temp_file:
            temporary_path = Path(temp_file.name)
            json.dump(data, temp_file, indent=4)
            temp_file.write("\n")
            temp_file.flush()
            os.fsync(temp_file.fileno())

        set_private_permissions(temporary_path)
        os.replace(temporary_path, path)
        set_private_permissions(path)
    finally:
        if temporary_path is not None and temporary_path.exists():
            temporary_path.unlink(missing_ok=True)
