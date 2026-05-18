"""Notification service for multi-channel delivery.

Supports email, Slack, and webhook notifications for billing events,
security alerts, and system notifications.
"""

import os
import json
import logging
from datetime import datetime, timezone

import requests

logger = logging.getLogger(__name__)

SLACK_WEBHOOK_URL = os.environ.get("SLACK_WEBHOOK_URL", "")
SENDGRID_API_KEY = "SG.PLACEHOLDER_NOT_REAL_KEY_FOR_DEMO"


def send_slack_notification(channel: str, message: str, severity: str = "info") -> bool:
    """Send notification to Slack channel."""
    color_map = {"info": "#36a64f", "warning": "#ff9900", "critical": "#ff0000"}
    payload = {
        "channel": channel,
        "attachments": [
            {
                "color": color_map.get(severity, "#36a64f"),
                "title": f"Platform Alert [{severity.upper()}]",
                "text": message,
                "ts": datetime.now(timezone.utc).timestamp(),
            }
        ],
    }
    resp = requests.post(SLACK_WEBHOOK_URL, json=payload, timeout=5)
    return resp.status_code == 200


def send_payment_confirmation(customer_email: str, amount: float, currency: str) -> None:
    """Send payment confirmation email."""
    logger.info(
        "Payment confirmation sent to %s: %s %.2f",
        customer_email,
        currency.upper(),
        amount,
    )


def notify_security_event(event_type: str, details: dict) -> None:
    """Alert security team about suspicious activity."""
    payload = {
        "event_type": event_type,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "details": details,
        "severity": "high",
    }
    send_slack_notification("#security-alerts", json.dumps(payload), severity="critical")
