import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from api.authorization import authorize_request


def test_authorization_cases():
    tests = [
        # ALLOW cases
        {
            "name": "HR reads employees",
            "scope": "read:employees",
            "required": "read:employees",
            "expected": "ALLOW",
        },
        {
            "name": "Finance reads transactions",
            "scope": "read:transactions",
            "required": "read:transactions",
            "expected": "ALLOW",
        },
        {
            "name": "IT updates systems",
            "scope": "update:systems",
            "required": "update:systems",
            "expected": "ALLOW",
        },

        # DENY cases
        {
            "name": "Finance reads employees",
            "scope": "read:transactions",
            "required": "read:employees",
            "expected": "DENY",
        },
        {
            "name": "HR reads transactions",
            "scope": "read:employees",
            "required": "read:transactions",
            "expected": "DENY",
        },
        {
            "name": "Sales reads systems",
            "scope": "read:reports",
            "required": "read:systems",
            "expected": "DENY",
        },
    ]

    print("\n=== Authorization Test Matrix ===\n")

    for test in tests:
        # Simulated decoded JWT payload
        payload = {
            "scope": test["scope"]
        }

        allowed = test["required"] in payload["scope"].split()

        result = "ALLOW" if allowed else "DENY"

        status = "PASS" if result == test["expected"] else "FAIL"

        print(
            f"{status} | "
            f"{test['name']} | "
            f"Required: {test['required']} | "
            f"Result: {result}"
        )


if __name__ == "__main__":
    test_authorization_cases()