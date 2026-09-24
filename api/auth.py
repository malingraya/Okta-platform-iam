import os
import ssl
import certifi
import requests
import jwt
from jwt import PyJWKClient
from dotenv import load_dotenv

load_dotenv()

DOMAIN = os.getenv("AUTH0_DOMAIN")

if not DOMAIN:
    raise ValueError("AUTH0_DOMAIN is missing from .env")

DOMAIN = DOMAIN.replace("https://", "").rstrip("/")

ISSUER = f"https://{DOMAIN}/"
AUDIENCE = "https://securehealth-api"

JWKS_URL = f"{ISSUER}.well-known/jwks.json"

# Use certifi's up-to-date CA bundle instead of the system's potentially expired certs
_ssl_context = ssl.create_default_context(cafile=certifi.where())
jwks_client = PyJWKClient(JWKS_URL, ssl_context=_ssl_context, cache_jwk_set=True, lifespan=300)


def validate_token(token, public_key=None, audience=AUDIENCE, issuer=ISSUER):
    """
    Validate a JWT using Auth0 JWKS or an explicit public key.
    
    Checks:
    - Signature (RS256)
    - Issuer (must match expected Auth0 tenant)
    - Audience (must match expected API audience)
    - Expiration time (exp)
    """
    if not token:
        raise Exception("Token missing")

    try:
        if public_key is None:
            signing_key = jwks_client.get_signing_key_from_jwt(token)
            key = signing_key.key
        else:
            key = public_key

        payload = jwt.decode(
            token,
            key,
            algorithms=["RS256"],
            audience=audience,
            issuer=issuer,
        )

        return payload

    except jwt.ExpiredSignatureError:
        raise Exception("Token expired")

    except jwt.InvalidAudienceError:
        raise Exception("Invalid audience")

    except jwt.InvalidIssuerError:
        raise Exception("Invalid issuer")

    except jwt.InvalidSignatureError:
        raise Exception("Invalid token signature")

    except jwt.InvalidTokenError as e:
        error_text = str(e)
        if "utf-8" in error_text.lower() or "codec" in error_text.lower():
            raise Exception("Received an Opaque Token instead of a JWT. To receive a valid JWT Access Token, you must log in with API audience 'https://securehealth-api'.")
        raise Exception(f"Invalid token: {e}")


def has_scope(payload, required_scope):
    """Check if required scope is present in the token's scope claim."""
    scope_string = payload.get("scope", "")
    scopes = scope_string.split()

    return required_scope in scopes