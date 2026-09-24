import csv
import os
import sys
from datetime import datetime

import requests

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT_ROOT)

from auth0_client import get_headers, MGMT_API_URL


CSV_FILE = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "employees.csv"
)

AUDIT_FILE = os.path.join(
    PROJECT_ROOT,
    "audit",
    "user_lifecycle.log"
)


def write_audit(action, employee_id, email, details):
    os.makedirs(os.path.dirname(AUDIT_FILE), exist_ok=True)

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    line = (
        f"{timestamp} | {action} | "
        f"{employee_id} | {email} | {details}\n"
    )

    with open(AUDIT_FILE, "a", encoding="utf-8") as file:
        file.write(line)


def user_exists(email):
    url = f"{MGMT_API_URL}/users-by-email"

    response = requests.get(
        url,
        headers=get_headers(),
        params={"email": email},
        timeout=30
    )

    if response.status_code != 200:
        print(f"⚠️ Could not check {email}")
        print(response.text)
        return False

    return len(response.json()) > 0


def create_user(employee):
    email = employee["Email"].strip()
    first_name = employee["FirstName"].strip()
    last_name = employee["LastName"].strip()
    department = employee["Department"].strip()
    title = employee["Title"].strip()
    manager = employee["Manager"].strip()
    status = employee["Status"].strip()

    # Generate employee ID from email for this lab
    employee_id = email.split("@")[0].upper()

    if user_exists(email):
        print(f"⚠️ Already exists: {email}")

        write_audit(
            "SKIP",
            employee_id,
            email,
            "User already exists"
        )

        return

    user_data = {
        "connection": "Username-Password-Authentication",
        "email": email,
        "password": "SecureHealth@123!",
        "email_verified": False,
        "user_metadata": {
            "employee_id": employee_id,
            "first_name": first_name,
            "last_name": last_name,
            "department": department,
            "job_title": title,
            "manager": manager,
            "status": status
        }
    }

    url = f"{MGMT_API_URL}/users"

    response = requests.post(
        url,
        headers=get_headers(),
        json=user_data,
        timeout=30
    )

    if response.status_code == 201:
        user = response.json()

        print(f"✅ Created: {email}")
        print(f"   User ID: {user.get('user_id')}")

        write_audit(
            "CREATE",
            employee_id,
            email,
            (
                f"Department={department} | "
                f"Job Title={title} | "
                f"Manager={manager} | "
                f"User ID={user.get('user_id')}"
            )
        )

    else:
        print(f"❌ Failed: {email}")
        print(f"   Status: {response.status_code}")
        print(f"   Response: {response.text}")

        write_audit(
            "CREATE_FAILED",
            employee_id,
            email,
            f"Status={response.status_code}"
        )


def main():
    print("=== SecureHealth IAM Bulk Provisioning ===")
    print()

    if not os.path.exists(CSV_FILE):
        print("❌ employees.csv not found")
        sys.exit(1)

    with open(CSV_FILE, "r", encoding="utf-8-sig") as file:
        reader = csv.DictReader(file)

        required_columns = {
            "FirstName",
            "LastName",
            "Email",
            "Department",
            "Title",
            "Manager",
            "Status"
        }

        actual_columns = set(reader.fieldnames or [])

        if not required_columns.issubset(actual_columns):
            print("❌ CSV columns are incorrect")
            print("Required:")
            print(required_columns)
            print("Found:")
            print(actual_columns)
            sys.exit(1)

        for employee in reader:
            create_user(employee)

    print()
    print("✅ Bulk provisioning completed")
    print(f"✅ Audit log: {AUDIT_FILE}")


if __name__ == "__main__":
    main()