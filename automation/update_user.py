import os
import sys
import requests

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT_ROOT)

from auth0_client import get_headers, MGMT_API_URL

USER_ID = "auth0|6aa0132c44040525eb1dd56e"

url = f"{MGMT_API_URL}/users/{USER_ID}"

update_data = {
    "user_metadata": {
        "employee_id": "EMP1001",
        "department": "Security",
        "job_title": "IAM Engineer"
    }
}

response = requests.patch(
    url,
    headers=get_headers(),
    json=update_data,
    timeout=30
)

if response.status_code == 200:
    user = response.json()

    print("✅ User updated successfully")
    print("Email:", user.get("email"))
    print("Department:", user.get("user_metadata", {}).get("department"))
    print("Job Title:", user.get("user_metadata", {}).get("job_title"))
else:
    print("❌ Update failed")
    print("Status:", response.status_code)
    print("Response:", response.text)