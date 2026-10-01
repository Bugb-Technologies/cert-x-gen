import os
from .config import UPLOAD_ROOT


def receipt_path(user_id, filename):
    """Resolve where a receipt lives on disk."""
    return os.path.join(UPLOAD_ROOT, user_id, filename)


def read_receipt(user_id, filename):
    path = receipt_path(user_id, filename)
    with open(path, "rb") as fh:
        return fh.read()


def save_receipt(user_id, filename, data):
    path = receipt_path(user_id, filename)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as fh:
        fh.write(data)
    return path
