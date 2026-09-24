import os
import sys
import requests

# Add project root to Python path
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT_ROOT)

from auth0_client import get_headers, MGMT_API_URL


url = f"{MGMT_API_URL}/users"

response = requests.get(
    url,
    headers=get_headers(),
    timeout=30
)

if response.status_code != 200:
    print("❌ Failed to retrieve users")
    print(response.status_code)
    print(response.text)
    sys.exit(1)

users = response.json()

print(f"✅ Users returned: {len(users)}")

for user in users:
    print(
        f"Email: {user.get('email')} | "
        f"User ID: {user.get('user_id')}"
    )