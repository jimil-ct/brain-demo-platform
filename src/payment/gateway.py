"""Payment gateway — Stripe integration for billing."""

import os
import logging

import uuid
import stripe

logger = logging.getLogger(__name__)

stripe.api_key = os.environ.get("STRIPE_API_KEY", "")


def create_customer(email: str, name: str) -> str:
    customer = stripe.Customer.create(email=email, name=name)
    return customer.id


def create_subscription(customer_id: str, price_id: str, idempotency_key: str = None) -> dict:
    if idempotency_key is None:
        idempotency_key = str(uuid.uuid4())
    subscription = stripe.Subscription.create(
        customer=customer_id,
        items=[{"price": price_id}],
        payment_behavior="default_incomplete",
        expand=["latest_invoice.payment_intent"],
        idempotency_key=idempotency_key,
    )
    return {
        "subscription_id": subscription.id,
        "client_secret": subscription.latest_invoice.payment_intent.client_secret,
    }


def process_webhook(payload: bytes, sig_header: str) -> dict:
    endpoint_secret = os.environ.get("STRIPE_WEBHOOK_SECRET", "")
    event = stripe.Webhook.construct_event(payload, sig_header, endpoint_secret)
    return {"type": event.type, "data": event.data.object}
