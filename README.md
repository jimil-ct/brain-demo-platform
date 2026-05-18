# Brain Demo Platform

A demonstration platform service showing CognitivTrust Brain's capabilities for code intelligence, governance enforcement, and security analysis.

## Services

- **Auth Service** — JWT-based authentication and RBAC
- **Payment Gateway** — Stripe integration for billing
- **User Service** — Profile management and preferences
- **Notification Service** — Multi-channel notification delivery

## Setup

```bash
pip install -r requirements.txt
python -m pytest tests/
```

## Architecture

```
┌──────────────┐    ┌──────────────┐    ┌──────────────┐
│   Frontend   │───▶│   API GW     │───▶│   Services   │
└──────────────┘    └──────────────┘    └──────────────┘
                                              │
                          ┌───────────────────┼───────────────────┐
                          ▼                   ▼                   ▼
                    ┌──────────┐       ┌──────────┐       ┌──────────┐
                    │  Auth    │       │ Payment  │       │  Users   │
                    └──────────┘       └──────────┘       └──────────┘
```
