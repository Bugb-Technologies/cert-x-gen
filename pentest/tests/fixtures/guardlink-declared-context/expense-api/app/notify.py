import requests
from .config import WEBHOOK_TIMEOUT


def send_webhook(url, payload):
    """POST an expense event to a team-configured webhook URL."""
    return requests.post(url, json=payload, timeout=WEBHOOK_TIMEOUT)


def fetch_exchange_rate(currency):
    resp = requests.get(
        f"https://api.exchangerate.host/latest?base={currency}",
        timeout=WEBHOOK_TIMEOUT,
    )
    return resp.json().get("rates", {})
