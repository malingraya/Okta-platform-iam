import os
import requests
from dotenv import load_dotenv

load_dotenv()

DOMAIN = os.getenv("AUTH0_DOMAIN")
CLIENT_ID = os.getenv("AUTH0_MGMT_CLIENT_ID")
CLIENT_SECRET = os.getenv("AUTH0_MGMT_CLIENT_SECRET")

MGMT_API_URL = f"https://{DOMAIN}/api/v2"


def get_access_token():
    token_url = f"https://{DOMAIN}/oauth/token"

    payload = {
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
        "audience": MGMT_API_URL + "/",
        "grant_type": "client_credentials"
    }

    response = requests.post(token_url, json=payload)

    if response.status_code != 200:
        raise Exception(
            f"Failed to obtain Auth0 token: "
            f"{response.status_code} {response.text}"
        )

    return response.json()["access_token"]


def get_headers():
    token = get_access_token()

    return {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }