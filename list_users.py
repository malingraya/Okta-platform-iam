import requests

from auth0.auth0_client import get_headers, MGMT_API_URL


url = f"{MGMT_API_URL}/users"

response = requests.get(
    url,
    headers=get_headers()
)

if response.status_code == 200:
    users = response.json()

    print("✅ read:users permission working")
    print(f"✅ Users returned: {len(users)}")

    for user in users:
        print(
            f"Email: {user.get('email')} | "
            f"User ID: {user.get('user_id')}"
        )

else:
    print("❌ Failed to read users")
    print(f"Status Code: {response.status_code}")
    print(response.text)