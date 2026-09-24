"""
API Security & JWT Validation Test Suite
Module 4 — OAuth 2.0, OIDC & JWT Security

Automated test collection for Task 6 and Task 7:
1. Valid access token with required scope (ALLOW -> 200 OK)
2. No token provided (DENY -> 401 Unauthorized)
3. Expired token (DENY -> 401 Unauthorized)
4. Wrong audience (DENY -> 401 Unauthorized)
5. Insufficient scope (DENY -> 403 Forbidden)
6. Wrong issuer (DENY -> 401 Unauthorized)
7. Invalid/Tampered signature (DENY -> 401 Unauthorized)

Can be executed standalone (`python tests/test_module4_api.py`)
or via standard unittest (`python -m unittest tests/test_module4_api.py`).
"""

import os
import sys
import time
import unittest
from unittest.mock import patch

# Ensure repository root is in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from starlette.testclient import TestClient
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import jwt

from api.server import app
from api.auth import AUDIENCE, ISSUER, validate_token


# ---------------------------------------------------------------------------
# Cryptographic Key Generation for Hermetic Offline Testing
# ---------------------------------------------------------------------------

def generate_rsa_keypair():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    priv_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pub_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return priv_pem, pub_pem


# Generate trusted mock IdP keypair and untrusted rogue keypair
TRUSTED_PRIV_KEY, TRUSTED_PUB_KEY = generate_rsa_keypair()
UNTRUSTED_PRIV_KEY, UNTRUSTED_PUB_KEY = generate_rsa_keypair()


def make_token(
    sub: str = "auth0|66fa81c00991427babcde123",
    aud: str = AUDIENCE,
    iss: str = ISSUER,
    scope: str = "read:employees",
    expires_in: int = 3600,
    signing_key: bytes = TRUSTED_PRIV_KEY,
) -> str:
    """Helper to mint RS256 JWTs with arbitrary claims."""
    now = int(time.time())
    payload = {
        "iss": iss,
        "sub": sub,
        "aud": aud,
        "iat": now,
        "exp": now + expires_in,
        "scope": scope,
        "azp": "8eTORf9FzsolQcwrHqyjrGmjyL9QErRu",
    }
    return jwt.encode(payload, signing_key, algorithm="RS256")


class TestModule4APISecurity(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(app)

    def _mock_token_validator(self, token, **kwargs):
        """Validates token using the trusted test public key."""
        return validate_token(token, public_key=TRUSTED_PUB_KEY, **kwargs)

    # -----------------------------------------------------------------------
    # Task 6: Valid Access Token with Required Scope (ALLOW)
    # -----------------------------------------------------------------------
    def test_01_valid_token_with_required_scope(self):
        """Case 1: Calling protected API with valid token & correct scope -> 200 OK (ALLOW)."""
        token = make_token(scope="read:employees")

        with patch("api.server.validate_token", side_effect=self._mock_token_validator):
            response = self.client.get(
                "/api/employees",
                headers={"Authorization": f"Bearer {token}"},
            )

        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["department"], "Human Resources")
        self.assertIn("records", data)
        self.assertGreaterEqual(len(data["records"]), 1)

    # -----------------------------------------------------------------------
    # Task 7: Negative Authorization & Authentication Test Cases
    # -----------------------------------------------------------------------
    def test_02_no_token_provided(self):
        """Case 2: Calling protected API with no token -> 401 Unauthorized."""
        response = self.client.get("/api/employees")

        self.assertEqual(response.status_code, 401)
        data = response.json()
        self.assertIn("401 Unauthorized", data["detail"])
        self.assertIn("Missing Authorization Bearer token", data["detail"])

    def test_03_expired_token(self):
        """Case 3: Calling protected API with expired token -> 401 Unauthorized."""
        # Token expired 60 seconds ago
        token = make_token(scope="read:employees", expires_in=-60)

        with patch("api.server.validate_token", side_effect=self._mock_token_validator):
            response = self.client.get(
                "/api/employees",
                headers={"Authorization": f"Bearer {token}"},
            )

        self.assertEqual(response.status_code, 401)
        data = response.json()
        self.assertIn("Token expired", data["detail"])

    def test_04_wrong_audience(self):
        """Case 4: Calling protected API with token meant for another audience -> 401 Unauthorized."""
        # Token issued for a different API audience
        token = make_token(aud="https://unrelated-thirdparty-api", scope="read:employees")

        with patch("api.server.validate_token", side_effect=self._mock_token_validator):
            response = self.client.get(
                "/api/employees",
                headers={"Authorization": f"Bearer {token}"},
            )

        self.assertEqual(response.status_code, 401)
        data = response.json()
        self.assertIn("Invalid audience", data["detail"])

    def test_05_insufficient_scope(self):
        """Case 5: Calling protected API with valid token but insufficient scope -> 403 Forbidden."""
        # Token has 'read:transactions' (Finance) but endpoint requires 'read:employees' (HR)
        token = make_token(scope="read:transactions")

        with patch("api.server.validate_token", side_effect=self._mock_token_validator):
            response = self.client.get(
                "/api/employees",
                headers={"Authorization": f"Bearer {token}"},
            )

        self.assertEqual(response.status_code, 403)
        data = response.json()
        self.assertIn("403 Forbidden", data["detail"])
        self.assertIn("Missing scope 'read:employees'", data["detail"])

    def test_06_wrong_issuer(self):
        """Case 6: Calling protected API with token from untrusted issuer -> 401 Unauthorized."""
        token = make_token(iss="https://rogue-tenant.auth0.com/", scope="read:employees")

        with patch("api.server.validate_token", side_effect=self._mock_token_validator):
            response = self.client.get(
                "/api/employees",
                headers={"Authorization": f"Bearer {token}"},
            )

        self.assertEqual(response.status_code, 401)
        data = response.json()
        self.assertIn("Invalid issuer", data["detail"])

    def test_07_invalid_signature(self):
        """Case 7: Calling protected API with token signed by untrusted key -> 401 Unauthorized."""
        # Signed with an untrusted rogue private key
        token = make_token(scope="read:employees", signing_key=UNTRUSTED_PRIV_KEY)

        with patch("api.server.validate_token", side_effect=self._mock_token_validator):
            response = self.client.get(
                "/api/employees",
                headers={"Authorization": f"Bearer {token}"},
            )

        self.assertEqual(response.status_code, 401)
        data = response.json()
        self.assertIn("401 Unauthorized", data["detail"])


# ---------------------------------------------------------------------------
# Standalone Runner with Formatted Console Report
# ---------------------------------------------------------------------------

def run_standalone_test_suite():
    print("=" * 85)
    print("  MODULE 4 -- PROTECTED API JWT SECURITY & SCOPE TEST SUITE")
    print("=" * 85)
    print(f"Target API Audience: {AUDIENCE}")
    print(f"Expected Issuer:     {ISSUER}")
    print("-" * 85)

    client = TestClient(app)

    def mock_validator(token, **kwargs):
        return validate_token(token, public_key=TRUSTED_PUB_KEY, **kwargs)

    test_cases = [
        {
            "num": "1",
            "name": "Valid Token + Required Scope",
            "token": make_token(scope="read:employees"),
            "endpoint": "/api/employees",
            "expected_status": 200,
            "expected_decision": "ALLOW",
            "expected_detail": None,
        },
        {
            "num": "2",
            "name": "No Token Provided",
            "token": None,
            "endpoint": "/api/employees",
            "expected_status": 401,
            "expected_decision": "DENY (401)",
            "expected_detail": "Missing Authorization Bearer token",
        },
        {
            "num": "3",
            "name": "Expired Token",
            "token": make_token(scope="read:employees", expires_in=-60),
            "endpoint": "/api/employees",
            "expected_status": 401,
            "expected_decision": "DENY (401)",
            "expected_detail": "Token expired",
        },
        {
            "num": "4",
            "name": "Wrong Audience",
            "token": make_token(aud="https://wrong-api", scope="read:employees"),
            "endpoint": "/api/employees",
            "expected_status": 401,
            "expected_decision": "DENY (401)",
            "expected_detail": "Invalid audience",
        },
        {
            "num": "5",
            "name": "Insufficient Scope",
            "token": make_token(scope="read:transactions"),
            "endpoint": "/api/employees",
            "expected_status": 403,
            "expected_decision": "DENY (403)",
            "expected_detail": "Missing scope 'read:employees'",
        },
        {
            "num": "6",
            "name": "Wrong Issuer",
            "token": make_token(iss="https://rogue-tenant.auth0.com/", scope="read:employees"),
            "endpoint": "/api/employees",
            "expected_status": 401,
            "expected_decision": "DENY (401)",
            "expected_detail": "Invalid issuer",
        },
        {
            "num": "7",
            "name": "Tampered / Invalid Signature",
            "token": make_token(scope="read:employees", signing_key=UNTRUSTED_PRIV_KEY),
            "endpoint": "/api/employees",
            "expected_status": 401,
            "expected_decision": "DENY (401)",
            "expected_detail": "signature",
        },
    ]

    all_passed = True
    print(f"{'#':<3} | {'Test Scenario':<30} | {'Expected':<12} | {'Actual':<12} | {'Status'}")
    print("-" * 85)

    with patch("api.server.validate_token", side_effect=mock_validator):
        for tc in test_cases:
            headers = {}
            if tc["token"]:
                headers["Authorization"] = f"Bearer {tc['token']}"

            resp = client.get(tc["endpoint"], headers=headers)
            actual_status = resp.status_code
            passed = actual_status == tc["expected_status"]

            if not passed:
                all_passed = False

            status_label = "PASS" if passed else "FAIL"
            print(
                f"{tc['num']:<3} | "
                f"{tc['name']:<30} | "
                f"{tc['expected_decision']:<12} | "
                f"HTTP {actual_status:<7} | "
                f"{status_label}"
            )
            if not passed:
                print(f"    --> Failure detail: {resp.text}")

    print("=" * 85)
    if all_passed:
        print("RESULT: ALL 7 TEST CASES PASSED SUCCESSFULLY.")
    else:
        print("RESULT: SOME TESTS FAILED.")
    print("=" * 85)


if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1 and sys.argv[1] == "--unittest":
        unittest.main(argv=[sys.argv[0]])
    else:
        run_standalone_test_suite()
