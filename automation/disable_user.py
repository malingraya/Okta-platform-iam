import os
import sys
import requests

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT_ROOT)

from auth0_client import get_headers, MGMT_API_URL

USER_ID = "auth0|6aa0132c44040525eb1dd56e"

url = f"{MGMT_API_URL}/users/{USER_ID}"

update_data = {
    "blocked": True
}

response = requests.patch(
    url,
    headers=get_headers(),
    json=update_data,
    timeout=30
)

if response.status_code == 200:
    print("✅ User disabled successfully")
    print("User ID:", USER_ID)
    print("Blocked: True")
else:
    print("❌ Disable failed")
    print("Status:", response.status_code)
    print("Response:", response.text)