import os
import sys
import requests

# Add project root to Python path
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT_ROOT)

from auth0_client import get_headers, MGMT_API_URL


# New employee details
user_data = {
    "connection": "Username-Password-Authentication",
    "email": "amit.sharma@securehealth.test",
    "password": "SecureHealth@123!",
    "email_verified": False,
    "user_metadata": {
        "employee_id": "EMP1001",
        "department": "IT",
        "job_title": "IAM Analyst"
    }
}


# Create user
url = f"{MGMT_API_URL}/users"

response = requests.post(
    url,
    headers=get_headers(),
    json=user_data,
    timeout=30
)

# Check result
if response.status_code == 201:
    user = response.json()

    print("✅ User created successfully")
    print("Email:", user.get("email"))
    print("User ID:", user.get("user_id"))
    print("Employee ID:", user.get("user_metadata", {}).get("employee_id"))
    print("Department:", user.get("user_metadata", {}).get("department"))
    print("Job Title:", user.get("user_metadata", {}).get("job_title"))

else:
    print("❌ User creation failed")
    print("Status:", response.status_code)
    print("Response:", response.text)