# SecureHealth IAM Platform (Okta / Auth0)

End-to-end IAM portfolio project using Auth0, OAuth 2.0, OIDC, API authorization, MFA, JML automation, and access governance.

## Project Structure

- `webapp/`: FastAPI web portal demonstrating OIDC sign-in, PKCE, token inspection, and API proxying.
- `api/`: FastAPI Protected Resource Server validating RS256 JWTs and fine-grained scopes (`read:employees`, `read:transactions`, etc.).
- `automation/`: Automation scripts including user lifecycle, bulk provisioning, and JWT claim decoder (`automation/decode_jwt.py`).
- `tests/`: Automated unit and security test suites verifying least-privilege scope authorization and token security.
- `docs/`: Module documentation, architecture specifications, and interview references.

---

## Modules

- **Module 1 & 2**: Auth0 Tenant & Environment Setup, User Lifecycle Management (JML).
- **Module 3**: [Authorization Design](docs/module3-authorization.md) — Permission matrices, custom API definitions, and least privilege modeling.
- **Module 4**: [OAuth 2.0, OIDC & JWT Security](docs/module4-oauth-oidc.md) — Working web app with PKCE, protected API, token claim breakdown, test collection, and interview guide.

---

## Quick Start (Module 4)

### 1. Run the Security & API Test Collection
```powershell
.\.venv\Scripts\python tests/test_module4_api.py
```

### 2. Inspect Sample ID & Access Tokens Locally
```powershell
.\.venv\Scripts\python automation/decode_jwt.py --sample
```

### 3. Run the Protected API Server (Port 8001)
```powershell
.\.venv\Scripts\python -m uvicorn api.server:app --port 8001 --reload
```

### 4. Run the SecureHealth Web Portal (Port 8000)
```powershell
.\.venv\Scripts\python -m uvicorn webapp.main:app --port 8000 --reload
```
Open `http://localhost:8000` to authenticate via Auth0 Universal Login and inspect tokens at `/tokens`.
