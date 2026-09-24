import os
import sys
import requests

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT_ROOT)

from auth0_client import get_headers, MGMT_API_URL

USER_ID = "auth0|6aa0132c44040525eb1dd56e"

url = f"{MGMT_API_URL}/users/{USER_ID}"

response = requests.get(
    url,
    headers=get_headers(),
    timeout=30
)

if response.status_code == 200:
    user = response.json()

    print("✅ User found successfully")
    print("Email:", user.get("email"))
    print("User ID:", user.get("user_id"))
    print("Blocked:", user.get("blocked"))
    print("Metadata:", user.get("user_metadata"))
else:
    print("❌ Failed to get user")
    print("Status:", response.status_code)
    print("Response:", response.text)