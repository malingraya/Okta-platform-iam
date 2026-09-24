"""
Token Inspector & JWT Decoder CLI
Module 4 — OAuth 2.0, OIDC & JWT Security

Safely decodes and explains JWT headers and claims (iss, aud, sub, exp, scope, azp)
without transmitting tokens over the network or exposing private keys.
Never commit live production tokens to source control.
"""

import argparse
import datetime
import json
import sys
import jwt

# Realistic synthetic tokens for SecureHealth (safe to commit; no real secrets)
SAMPLE_ID_TOKEN_PAYLOAD = {
    "iss": "https://dev-ol7m540dysftaa5e.us.auth0.com/",
    "sub": "auth0|66fa81c00991427babcde123",
    "aud": "8eTORf9FzsolQcwrHqyjrGmjyL9QErRu",
    "iat": 1727000000,
    "exp": 1727036000,
    "name": "Dr. Sarah Mitchell",
    "nickname": "sarah.mitchell",
    "email": "sarah.mitchell@securehealth.org",
    "email_verified": True,
    "sid": "Vp_yW31cQnQ-example-session-id",
}

SAMPLE_ACCESS_TOKEN_PAYLOAD = {
    "iss": "https://dev-ol7m540dysftaa5e.us.auth0.com/",
    "sub": "auth0|66fa81c00991427babcde123",
    "aud": "https://securehealth-api",
    "iat": 1727000000,
    "exp": 1727003600,
    "scope": "openid profile email read:employees update:employees",
    "azp": "8eTORf9FzsolQcwrHqyjrGmjyL9QErRu",
    "gty": "authorization_code",
}

CLAIM_EXPLANATIONS = {
    "iss": {
        "title": "Issuer (iss)",
        "meaning": "The identity authority that generated and signed this token.",
        "security_check": "API must verify this matches the trusted Auth0 domain with trailing slash.",
    },
    "sub": {
        "title": "Subject (sub)",
        "meaning": "The unique, immutable identifier representing the authenticated end-user.",
        "security_check": "Used by databases and audit trails to identify who performed an action.",
    },
    "aud": {
        "title": "Audience (aud)",
        "meaning": "The intended recipient of the token.",
        "security_check": "CRITICAL: ID Token aud must be the Client ID. Access Token aud must be the API Identifier (https://securehealth-api). APIs must reject tokens not intended for them.",
    },
    "exp": {
        "title": "Expiration Time (exp)",
        "meaning": "Unix epoch timestamp after which the token is invalid.",
        "security_check": "APIs reject requests where current_time >= exp to prevent replay of old tokens.",
    },
    "iat": {
        "title": "Issued At (iat)",
        "meaning": "Unix epoch timestamp when the token was created.",
        "security_check": "Prevents tokens with future issuance dates and measures token age.",
    },
    "scope": {
        "title": "Scope (scope)",
        "meaning": "Space-separated list of delegated OAuth 2.0 permissions granted by the user.",
        "security_check": "API endpoints inspect this claim to enforce Least Privilege (e.g., read:employees).",
    },
    "azp": {
        "title": "Authorized Party (azp)",
        "meaning": "The Client ID of the application that requested the token via authorization code.",
        "security_check": "Ensures the token was issued to an authorized client application.",
    },
    "email": {
        "title": "Email",
        "meaning": "The authenticated user's email address (OIDC standard claim).",
        "security_check": "Only present in ID token when 'email' scope is requested.",
    },
    "email_verified": {
        "title": "Email Verified",
        "meaning": "Boolean flag stating whether user confirmed ownership of their email address.",
        "security_check": "Applications can block unverified accounts from sensitive actions.",
    },
}


def format_timestamp(ts):
    if not isinstance(ts, (int, float)):
        return str(ts)
    dt = datetime.datetime.fromtimestamp(ts, tz=datetime.timezone.utc)
    return f"{ts} ({dt.strftime('%Y-%m-%d %H:%M:%S UTC')})"


def explain_token(token_str: str = None, synthetic_payload: dict = None, token_type: str = "Token"):
    print("=" * 80)
    print(f"  JWT CLAIM INSPECTION REPORT -- {token_type.upper()}")
    print("=" * 80)

    header = {}
    payload = {}

    if token_str:
        try:
            header = jwt.get_unverified_header(token_str)
            payload = jwt.decode(token_str, options={"verify_signature": False})
        except Exception as e:
            print(f"Error decoding JWT: {e}")
            return
    elif synthetic_payload:
        header = {"alg": "RS256", "typ": "JWT", "kid": "sample-key-id-auth0"}
        payload = synthetic_payload

    print("\n[1] HEADER (JOSE Header):")
    print(json.dumps(header, indent=4))

    print("\n[2] PAYLOAD (Claims):")
    print(json.dumps(payload, indent=4))

    print("\n[3] IN-DEPTH CLAIM BREAKDOWN:")
    print("-" * 80)
    for claim_key, claim_val in payload.items():
        explanation = CLAIM_EXPLANATIONS.get(claim_key)
        val_display = format_timestamp(claim_val) if claim_key in ("exp", "iat", "nbf", "auth_time") else claim_val

        if explanation:
            print(f"* {explanation['title']}:")
            print(f"    Value:          {val_display}")
            print(f"    Role:           {explanation['meaning']}")
            print(f"    Security Check: {explanation['security_check']}")
        else:
            print(f"* {claim_key}:")
            print(f"    Value:          {val_display}")
        print()

    print("=" * 80)


def main():
    parser = argparse.ArgumentParser(
        description="Decode and inspect JWT claims locally for OAuth 2.0 / OIDC security analysis."
    )
    parser.add_argument("--token", "-t", type=str, help="Raw JWT string to inspect.")
    parser.add_argument(
        "--sample", "-s", action="store_true",
        help="Inspect standard synthetic ID Token and Access Token samples."
    )

    args = parser.parse_args()

    if args.token:
        explain_token(token_str=args.token, token_type="Provided JWT")
    elif args.sample or len(sys.argv) == 1:
        print("\n>>> Analyzing Sample OIDC ID Token (Identity) <<<")
        explain_token(synthetic_payload=SAMPLE_ID_TOKEN_PAYLOAD, token_type="OIDC ID Token")

        print("\n>>> Analyzing Sample OAuth 2.0 Access Token (Authorization) <<<")
        explain_token(synthetic_payload=SAMPLE_ACCESS_TOKEN_PAYLOAD, token_type="OAuth 2.0 API Access Token")
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
