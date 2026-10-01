import os

SECRET_KEY = os.environ.get("EXPENSE_SECRET", "dev-secret-change-me")
DB_PATH = os.environ.get("EXPENSE_DB", "expenses.db")
UPLOAD_ROOT = os.environ.get("EXPENSE_UPLOADS", "./uploads")
WEBHOOK_TIMEOUT = 10


def is_production() -> bool:
    return os.environ.get("ENV") == "production"
