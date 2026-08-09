"""
Automated Pytest Suite for QRIshield Reputation Engine
"""

import pytest
from fastapi.testclient import TestClient
from app.main import app
from app.core.reputation.scorer import analyse_target

client = TestClient(app)


def test_health_endpoint():
    response = client.get("/api/v1/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"


def test_invalid_input():
    res = analyse_target("notaurl")
    assert res["verdict"] == "INVALID"


def test_upi_vpa_legit():
    res = analyse_target("shop@okaxis")
    assert res["verdict"] == "SAFE"


def test_upi_vpa_suspicious():
    res = analyse_target("customer-care-refund@ybl")
    assert res["verdict"] == "SUSPICIOUS"
    assert any("fraud-associated keyword" in f for f in res["flags"])


def test_upi_deeplink_safe():
    res = analyse_target("upi://pay?pa=merchant@paytm&pn=Store")
    assert res["verdict"] == "SAFE"


def test_upi_deeplink_dangerous():
    res = analyse_target("upi://pay?pa=support-refund@ybl&am=9999&tn=Claim+Cashback")
    assert res["verdict"] == "DANGEROUS"


def test_at_obfuscation_attack():
    res = analyse_target("http://paypal.com@attacker.com/login")
    assert res["verdict"] == "DANGEROUS"
    assert any("CRITICAL: @ symbol obfuscation" in f for f in res["flags"])


def test_api_reputation_endpoint():
    response = client.post("/api/v1/reputation", json={"target": "http://192.168.1.1/upi/pay"})
    assert response.status_code == 200
    data = response.json()
    assert data["verdict"] == "DANGEROUS"
    assert data["has_ip_in_url"] is True
