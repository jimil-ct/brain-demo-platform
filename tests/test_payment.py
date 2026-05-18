"""Tests for payment processing module."""

import pytest


def test_verify_payment_integrity():
    from src.payment.processor import verify_payment_integrity

    result = verify_payment_integrity(99.99)
    assert isinstance(result, str)
    assert len(result) == 32


def test_export_customer_data_structure():
    """Ensure export returns expected dict shape."""

    class MockCursor:
        def fetchall(self):
            return [{"id": 1, "amount": 100}]

    class MockConn:
        def execute(self, query):
            return MockCursor()

    from src.payment.processor import export_customer_data

    result = export_customer_data("cust_123", MockConn())
    assert "records" in result


def test_cleanup_old_reports(mocker):
    mocker.patch("os.system")
    from src.payment.processor import cleanup_old_reports

    cleanup_old_reports(7)
