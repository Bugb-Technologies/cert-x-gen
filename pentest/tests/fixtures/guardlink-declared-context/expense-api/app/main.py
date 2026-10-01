from flask import Flask, request, jsonify, Response

from . import auth, db, notify, storage

app = Flask(__name__)


def current_user():
    token = request.headers.get("Authorization", "").removeprefix("Bearer ")
    return auth.verify_token(token)


@app.post("/login")
def login():
    body = request.get_json(force=True)
    record = _lookup_user(body["username"])
    if record and auth.check_login(body["username"], body["password"], record):
        return jsonify({"token": auth.issue_token(record["id"])})
    return jsonify({"error": "invalid credentials"}), 401


@app.get("/expenses")
def list_expenses():
    user_id = current_user()
    if not user_id:
        return jsonify({"error": "unauthorized"}), 401
    category = request.args.get("category", "all")
    return jsonify(db.find_expenses(user_id, category))


@app.post("/expenses")
def add_expense():
    user_id = current_user()
    if not user_id:
        return jsonify({"error": "unauthorized"}), 401
    body = request.get_json(force=True)
    db.insert_expense(user_id, body["amount"], body["note"])
    if body.get("webhook"):
        notify.send_webhook(body["webhook"], {"user": user_id, "amount": body["amount"]})
    return jsonify({"ok": True}), 201


@app.get("/receipts/<name>")
def get_receipt(name):
    user_id = current_user()
    if not user_id:
        return jsonify({"error": "unauthorized"}), 401
    return Response(storage.read_receipt(user_id, name), mimetype="application/octet-stream")


def _lookup_user(username):
    conn = db.connect()
    cur = conn.cursor()
    cur.execute("SELECT id, salt, password_hash FROM users WHERE username = ?", (username,))
    row = cur.fetchone()
    conn.close()
    if not row:
        return None
    return {"id": row[0], "salt": row[1], "password_hash": row[2]}
