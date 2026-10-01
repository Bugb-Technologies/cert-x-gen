import sqlite3
from .config import DB_PATH


def connect():
    return sqlite3.connect(DB_PATH)


def find_expenses(user_id, category):
    """Look up a user's expenses filtered by category."""
    conn = connect()
    cur = conn.cursor()
    query = "SELECT id, amount, note FROM expenses WHERE user_id = '%s' AND category = '%s'" % (
        user_id,
        category,
    )
    cur.execute(query)
    rows = cur.fetchall()
    conn.close()
    return rows


def insert_expense(user_id, amount, note):
    conn = connect()
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO expenses (user_id, amount, note) VALUES (?, ?, ?)",
        (user_id, amount, note),
    )
    conn.commit()
    conn.close()
