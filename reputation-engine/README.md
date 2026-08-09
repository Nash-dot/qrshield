# QRIshield Threat Detection Engine

Independent URL Reputation & UPI Payment Fraud Analysis Platform for **QRIshield**.

---

## 🚀 Project Overview

`qrishield-backend` is a FastAPI-based backend service designed to detect QRishing, malicious URL redirects, and UPI payment scams in real-time **without third-party API dependencies**.

### Features

- 🛡️ **Zero API Dependency**: Independent WHOIS domain age and SSL validation.
- 📱 **UPI Deep Link Analysis**: Intercepts `upi://pay` payloads (`pa=`, `am=`, `tn=`).
- 💳 **UPI VPA Verification**: Validates `user@handle` syntax & fraud keywords.
- ⚠️ **Obfuscation Detection**: Flags `@` symbol spoofing attacks (`http://paypal.com@attacker.com`).
- ⚡ **FastAPI High Performance**: Async routes with OpenAPI swagger docs (`/docs`).

---

## 📁 Directory Structure

```
qrishield-backend/
├── app/
│   ├── main.py                   # FastAPI app entry point
│   ├── api/
│   │   ├── routes.py             # API endpoints (/reputation, /health)
│   │   └── schemas.py            # Pydantic request/response models
│   └── core/
│       └── reputation/           # Module 1: Reputation Engine
│           ├── whois_check.py    # WHOIS domain age validation
│           ├── ssl_check.py      # SSL certificate check
│           ├── url_features.py   # IP in URL, shortener, hosting, @ attack checks
│           ├── vpa_check.py      # UPI VPA syntax & upi:// parser
│           └── scorer.py         # Main engine scorer & verdict tiering
├── tests/
│   └── test_reputation.py        # Pytest unit tests
├── requirements.txt
└── README.md
```

---

## 🛠️ Local Setup & Running

### 1. Install Dependencies
```bash
pip install -r requirements.txt
```

### 2. Run the FastAPI Development Server
```bash
uvicorn app.main:app --reload --port 8000
```
Open [http://localhost:8000/docs](http://localhost:8000/docs) in your browser to view interactive API documentation.

### 3. Run Automated Tests
```bash
pytest tests/
```

---

## 📡 API Example Usage

### Endpoint: `POST /api/v1/reputation`

#### Request Payload:
```json
{
  "target": "upi://pay?pa=support-refund@ybl&am=9999&tn=Claim+Cashback"
}
```

#### Response:
```json
{
  "url": "upi://pay?pa=support-refund@ybl&am=9999&tn=Claim+Cashback",
  "domain": "upi://",
  "score": 65,
  "verdict": "DANGEROUS",
  "payee_vpa": "support-refund@ybl",
  "pre_filled_amount": "9999",
  "note": "Claim Cashback",
  "flags": [
    "VPA username contains fraud-associated keyword(s): refund",
    "Pre-filled payment amount detected: ₹9999 — verify before paying",
    "Transaction note contains suspicious keyword(s): cashback"
  ]
}
```
