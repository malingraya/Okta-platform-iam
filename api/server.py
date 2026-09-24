"""
SecureHealth Protected API Server
Module 4 — OAuth 2.0, OIDC & JWT Security

FastAPI Resource Server enforcing JWT signature verification (RS256),
issuer & audience validation, and fine-grained scope authorization.
"""

import os
from typing import Optional
from fastapi import FastAPI, Depends, HTTPException, Security
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from dotenv import load_dotenv

from api.auth import validate_token, has_scope, AUDIENCE, ISSUER

load_dotenv()

app = FastAPI(
    title="SecureHealth Protected API",
    description="Resource server demonstrating OAuth 2.0 Bearer JWT authentication and scope-based authorization.",
    version="1.0.0",
)

# HTTP Bearer scheme (auto_error=False allows custom 401 responses)
security = HTTPBearer(auto_error=False)


def get_current_payload(
    credentials: Optional[HTTPAuthorizationCredentials] = Security(security)
) -> dict:
    """
    Extract and validate the Bearer JWT from Authorization header.
    Validates signature via Auth0 JWKS, issuer, audience, and expiration.
    Returns decoded JWT payload dictionary if valid.
    """
    if credentials is None:
        raise HTTPException(
            status_code=401,
            detail="401 Unauthorized: Missing Authorization Bearer token",
            headers={"WWW-Authenticate": 'Bearer error="invalid_token", error_description="Missing token"'},
        )

    token = credentials.credentials

    try:
        payload = validate_token(token)
        return payload
    except Exception as e:
        error_msg = str(e)
        raise HTTPException(
            status_code=401,
            detail=f"401 Unauthorized: {error_msg}",
            headers={"WWW-Authenticate": f'Bearer error="invalid_token", error_description="{error_msg}"'},
        )


def require_scope(required_scope: str):
    """
    Dependency factory that checks if the caller's JWT contains the required scope.
    Returns 403 Forbidden if the scope is absent.
    """
    def scope_checker(payload: dict = Depends(get_current_payload)) -> dict:
        if not has_scope(payload, required_scope):
            raise HTTPException(
                status_code=403,
                detail=f"403 Forbidden: Insufficient permissions. Missing scope '{required_scope}'",
                headers={"WWW-Authenticate": f'Bearer error="insufficient_scope", scope="{required_scope}"'},
            )
        return payload

    return scope_checker


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@app.get("/api/public")
def public_endpoint():
    """Unprotected endpoint accessible to anyone."""
    return {
        "status": "online",
        "api": "SecureHealth API",
        "authentication": "None required",
        "message": "Welcome to the SecureHealth Public Service",
    }


@app.get("/api/me")
def get_caller_identity(payload: dict = Depends(get_current_payload)):
    """Protected endpoint returning the caller's token claims."""
    return {
        "sub": payload.get("sub"),
        "aud": payload.get("aud"),
        "iss": payload.get("iss"),
        "scopes": payload.get("scope", "").split(),
        "client_id": payload.get("azp") or payload.get("client_id"),
    }


@app.get("/api/employees")
def get_employees(payload: dict = Depends(require_scope("read:employees"))):
    """Protected endpoint for HR: requires 'read:employees' scope."""
    return {
        "department": "Human Resources",
        "authorized_subject": payload.get("sub"),
        "records": [
            {"id": "EMP-001", "name": "Alice Johnson", "role": "Cardiologist", "status": "Active"},
            {"id": "EMP-002", "name": "Bob Smith", "role": "Radiologist", "status": "Active"},
            {"id": "EMP-003", "name": "Clara Davis", "role": "Pediatrician", "status": "On Leave"},
        ],
    }


@app.post("/api/employees")
def update_employee(payload: dict = Depends(require_scope("update:employees"))):
    """Protected endpoint for HR: requires 'update:employees' scope."""
    return {
        "department": "Human Resources",
        "authorized_subject": payload.get("sub"),
        "status": "success",
        "message": "Employee record updated successfully.",
    }


@app.get("/api/transactions")
def get_transactions(payload: dict = Depends(require_scope("read:transactions"))):
    """Protected endpoint for Finance: requires 'read:transactions' scope."""
    return {
        "department": "Finance",
        "authorized_subject": payload.get("sub"),
        "records": [
            {"txn_id": "TXN-8801", "amount": 1450.00, "category": "Medical Supplies", "status": "Settled"},
            {"txn_id": "TXN-8802", "amount": 9200.50, "category": "Lab Equipment", "status": "Settled"},
        ],
    }


@app.get("/api/systems")
def get_systems(payload: dict = Depends(require_scope("read:systems"))):
    """Protected endpoint for IT: requires 'read:systems' scope."""
    return {
        "department": "Information Technology",
        "authorized_subject": payload.get("sub"),
        "systems": [
            {"system": "EHR-Database", "uptime": "99.98%", "status": "Healthy"},
            {"system": "Auth0-IdP-Bridge", "uptime": "100.0%", "status": "Healthy"},
            {"system": "PACS-Imaging-Server", "uptime": "99.95%", "status": "Healthy"},
        ],
    }


@app.get("/api/reports")
def get_reports(payload: dict = Depends(require_scope("read:reports"))):
    """Protected endpoint for Sales: requires 'read:reports' scope."""
    return {
        "department": "Sales",
        "authorized_subject": payload.get("sub"),
        "reports": [
            {"quarter": "Q1", "new_clinic_partnerships": 14, "retention_rate": "98.2%"},
            {"quarter": "Q2", "new_clinic_partnerships": 19, "retention_rate": "99.1%"},
        ],
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("api.server:app", host="127.0.0.1", port=8001, reload=True)
