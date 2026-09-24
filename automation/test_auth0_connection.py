import os
import requests
from dotenv import load_dotenv

load_dotenv()

domain = os.getenv("AUTH0_DOMAIN")
client_id = os.getenv("AUTH0_MGMT_CLIENT_ID")
client_secret = os.getenv("AUTH0_MGMT_CLIENT_SECRET")

if not domain:
    raise ValueError("AUTH0_DOMAIN is missing from .env")

if not client_id:
    raise ValueError("AUTH0_MGMT_CLIENT_ID is missing from .env")

if not client_secret:
    raise ValueError("AUTH0_MGMT_CLIENT_SECRET is missing from .env")

domain = domain.replace("https://", "").rstrip("/")

token_url = f"https://{domain}/oauth/token"

payload = {
    "client_id": client_id,
    "client_secret": client_secret,
    "audience": f"https://{domain}/api/v2/",
    "grant_type": "client_credentials"
}

print("Connecting to Auth0...")
print(f"Domain: {domain}")

response = requests.post(
    token_url,
    json=payload,
    timeout=30
)

print(f"Auth0 response status: {response.status_code}")

if response.status_code != 200:
    print("Auth0 response:")
    print(response.text)
    response.raise_for_status()

access_token = response.json()["access_token"]

print("✅ Auth0 connection successful!")
print("✅ Management API access token received.")