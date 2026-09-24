"""
SecureHealth Web Application
Module 4 — OAuth 2.0, OIDC & JWT Security

FastAPI web application implementing:
- OpenID Connect (OIDC) sign-in via Auth0 Universal Login
- Authorization Code Flow with PKCE (Proof Key for Code Exchange)
- Token inspection (/tokens) comparing ID Token and Access Token
- Protected API integration (/call-api) with Bearer token authentication
- Federated OIDC logout (/logout)
"""

import json
import os
import urllib.parse
from dotenv import load_dotenv
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from starlette.middleware.sessions import SessionMiddleware
from authlib.integrations.starlette_client import OAuth
import httpx
import jwt

load_dotenv()

# --------------------------------------------------
# Configuration
# --------------------------------------------------

AUTH0_DOMAIN = os.getenv("AUTH0_DOMAIN")
if AUTH0_DOMAIN:
    AUTH0_DOMAIN = AUTH0_DOMAIN.replace("https://", "").rstrip("/")

AUTH0_CLIENT_ID = os.getenv("AUTH0_WEB_CLIENT_ID") or os.getenv("AUTH0_CLIENT_ID")
AUTH0_CLIENT_SECRET = os.getenv("AUTH0_WEB_CLIENT_SECRET") or os.getenv("AUTH0_CLIENT_SECRET")
AUTH0_CALLBACK_URL = os.getenv("AUTH0_CALLBACK_URL", "http://localhost:8000/callback")
AUTH0_AUDIENCE = os.getenv("AUTH0_AUDIENCE", "https://securehealth-api")
PROTECTED_API_URL = os.getenv("PROTECTED_API_URL", "http://localhost:8001/api/employees")

# Robust session secret fallback for dev environment
SESSION_SECRET = os.getenv("SESSION_SECRET", "securehealth-oidc-super-secret-session-key-dev-3a4e")

if not AUTH0_DOMAIN:
    raise RuntimeError("AUTH0_DOMAIN is missing from .env")

if not AUTH0_CLIENT_ID:
    raise RuntimeError("AUTH0_CLIENT_ID is missing from .env")

# --------------------------------------------------
# FastAPI App & Session Middleware
# --------------------------------------------------

app = FastAPI(title="SecureHealth Web Portal")

app.add_middleware(
    SessionMiddleware,
    secret_key=SESSION_SECRET,
    max_age=3600,
)

# --------------------------------------------------
# Auth0 OAuth / OIDC Setup with PKCE
# --------------------------------------------------

oauth = OAuth()

oauth.register(
    name="auth0",
    client_id=AUTH0_CLIENT_ID,
    client_secret=AUTH0_CLIENT_SECRET,
    server_metadata_url=f"https://{AUTH0_DOMAIN}/.well-known/openid-configuration",
    client_kwargs={
        "scope": "openid profile email read:employees",
        "code_challenge_method": "S256",  # Enforce PKCE (RFC 7636)
    },
)

# --------------------------------------------------
# Helper Functions
# --------------------------------------------------

def decode_token_unverified(token_str: str) -> dict:
    """Decode JWT header and payload without signature verification for display purposes."""
    if not token_str:
        return {}
    try:
        header = jwt.get_unverified_header(token_str)
        payload = jwt.decode(token_str, options={"verify_signature": False})
        return {"header": header, "payload": payload}
    except Exception as e:
        return {"error": f"Failed to parse token: {e}"}


def get_base_css() -> str:
    return """
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; margin: 0; padding: 20px 40px; background: #f8fafc; color: #1e293b; }
        header { border-bottom: 2px solid #e2e8f0; padding-bottom: 15px; margin-bottom: 25px; display: flex; justify-content: space-between; align-items: center; }
        h1 { margin: 0; color: #0f172a; font-size: 24px; }
        .badge { background: #0284c7; color: white; padding: 4px 10px; border-radius: 9999px; font-size: 12px; font-weight: 600; text-transform: uppercase; }
        .card { background: white; border-radius: 8px; padding: 24px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); margin-bottom: 20px; border: 1px solid #e2e8f0; }
        .btn { display: inline-block; background: #2563eb; color: white; padding: 10px 18px; border-radius: 6px; text-decoration: none; font-weight: 500; font-size: 14px; border: none; cursor: pointer; }
        .btn:hover { background: #1d4ed8; }
        .btn-outline { background: transparent; color: #475569; border: 1px solid #cbd5e1; margin-left: 8px; }
        .btn-outline:hover { background: #f1f5f9; }
        .btn-danger { background: #ef4444; }
        .btn-danger:hover { background: #dc2626; }
        pre { background: #0f172a; color: #f8fafc; padding: 16px; border-radius: 6px; overflow-x: auto; font-size: 13px; line-height: 1.5; }
        .grid { display: grid; grid-template-columns: 1fr 1fr; gap: 20px; }
        .tag { display: inline-block; background: #e0f2fe; color: #0369a1; padding: 2px 8px; border-radius: 4px; font-size: 12px; font-weight: 600; margin-right: 4px; }
        table { width: 100%; border-collapse: collapse; margin-top: 15px; }
        th, td { text-align: left; padding: 10px; border-bottom: 1px solid #e2e8f0; font-size: 14px; }
        th { background: #f1f5f9; color: #475569; }
        .nav-links a { margin-right: 15px; text-decoration: none; color: #2563eb; font-weight: 500; }
        .nav-links a:hover { text-decoration: underline; }
    </style>
    """

# --------------------------------------------------
# Routes
# --------------------------------------------------

@app.get("/", response_class=HTMLResponse)
async def home(request: Request):
    user = request.session.get("user")
    token_dict = request.session.get("token", {})
    has_token = bool(token_dict.get("access_token") or token_dict.get("id_token"))

    if user:
        return f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>SecureHealth Portal — Authenticated</title>
            {get_base_css()}
        </head>
        <body>
            <header>
                <div>
                    <h1>SecureHealth Portal</h1>
                    <span style="font-size: 13px; color: #64748b;">Module 4: OAuth 2.0, OIDC & JWT Security</span>
                </div>
                <div>
                    <span class="badge">Authenticated</span>
                </div>
            </header>

            <div class="nav-links" style="margin-bottom: 20px;">
                <a href="/">Dashboard</a>
                <a href="/tokens">Token Inspector (ID vs Access Token)</a>
                <a href="/call-api">Call Protected API</a>
                <a href="/logout" style="color: #ef4444;">Logout</a>
            </div>

            <div class="card">
                <h2>Welcome, {user.get("name", user.get("nickname", "Authorized User"))}!</h2>
                <p>You have successfully authenticated via Auth0 Universal Login using <strong>Authorization Code Flow with PKCE</strong>.</p>
                <table>
                    <tr><th>Claim</th><th>Value</th></tr>
                    <tr><td><strong>User Name</strong></td><td>{user.get("name", "N/A")}</td></tr>
                    <tr><td><strong>Email</strong></td><td>{user.get("email", "N/A")}</td></tr>
                    <tr><td><strong>Subject (sub)</strong></td><td><code>{user.get("sub", "N/A")}</code></td></tr>
                    <tr><td><strong>Email Verified</strong></td><td>{user.get("email_verified", "N/A")}</td></tr>
                </table>
            </div>

            <div class="card">
                <h3>Actions</h3>
                <p>Explore your OAuth 2.0 / OIDC session credentials:</p>
                <a href="/tokens" class="btn">Inspect Captured Tokens</a>
                <a href="/call-api" class="btn btn-outline">Call Protected Health API</a>
                <a href="/logout" class="btn btn-danger" style="margin-left: 8px;">Log Out</a>
            </div>
        </body>
        </html>
        """

    return f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>SecureHealth Portal — Login</title>
        {get_base_css()}
    </head>
    <body>
        <header>
            <div>
                <h1>SecureHealth Portal</h1>
                <span style="font-size: 13px; color: #64748b;">Module 4: OAuth 2.0, OIDC & JWT Security</span>
            </div>
            <div>
                <span class="badge" style="background: #64748b;">Unauthenticated</span>
            </div>
        </header>

        <div class="card" style="max-width: 600px; margin: 40px auto; text-align: center;">
            <div style="font-size: 48px; margin-bottom: 15px;">🔒</div>
            <h2>SecureHealth IAM Authentication</h2>
            <p style="color: #64748b; line-height: 1.6;">
                This application demonstrates modern enterprise Single Sign-On (SSO) using
                <strong>OpenID Connect (OIDC)</strong>, <strong>Authorization Code Flow with PKCE</strong>,
                and JWT-based API authorization against the SecureHealth Resource Server.
            </p>

            <div style="background: #f8fafc; border: 1px dashed #cbd5e1; padding: 15px; border-radius: 6px; margin: 20px 0; text-align: left; font-size: 13px;">
                <strong>Active OAuth Configuration:</strong><br>
                &bull; IdP Domain: <code>{AUTH0_DOMAIN}</code><br>
                &bull; Flow: <code>Authorization Code + PKCE (S256)</code><br>
                &bull; Target API Audience: <code>{AUTH0_AUDIENCE}</code><br>
                &bull; Scopes Requested: <code>openid profile email read:employees</code>
            </div>

            <div style="margin-top: 20px;">
                <a href="/login" class="btn" style="padding: 12px 24px; font-size: 15px;">
                    Log In with Auth0 (OIDC + API Access)
                </a>
                <div style="margin-top: 10px;">
                    <a href="/login?api=false" style="font-size: 13px; color: #64748b; text-decoration: underline;">
                        Or test basic OIDC Login (No API Audience)
                    </a>
                </div>
            </div>
        </div>
    </body>
    </html>
    """


@app.get("/login")
async def login(request: Request, api: bool = True):
    """Initiate Authorization Code Flow with PKCE."""
    auth0 = oauth.create_client("auth0")
    
    actual_callback = str(request.url_for("callback"))
    callback_url = os.getenv("AUTH0_CALLBACK_URL") if str(request.base_url).startswith("http://localhost:8000") and os.getenv("AUTH0_CALLBACK_URL") else actual_callback

    extra_params = {}
    if api and AUTH0_AUDIENCE:
        extra_params["audience"] = AUTH0_AUDIENCE

    return await auth0.authorize_redirect(
        request,
        callback_url,
        **extra_params,
    )


@app.get("/callback")
async def callback(request: Request):
    """Handle the authorization code callback from Auth0 and exchange code for tokens."""
    auth0 = oauth.create_client("auth0")
    try:
        token = await auth0.authorize_access_token(request)
    except Exception as e:
        error_msg = str(e)
        is_api_auth_error = "is not authorized to access resource server" in error_msg
        is_par_error = "Pushed Authorization Requests" in error_msg

        guidance_box = ""
        if is_par_error:
            guidance_box = f"""
            <div style="background: #fef2f2; border: 1px solid #fecaca; border-radius: 8px; padding: 20px; margin: 20px 0; text-align: left;">
                <h4 style="color: #991b1b; margin-top: 0;">How to Fix in Auth0 Dashboard (PAR setting is enabled):</h4>
                <ol style="color: #7f1d1d; font-size: 14px; line-height: 1.8;">
                    <li>Log in to your <strong>Auth0 Dashboard</strong>.</li>
                    <li>In the left sidebar, click <strong>Applications &rarr; Applications</strong>.</li>
                    <li>Click on your application (<code>{AUTH0_CLIENT_ID}</code>).</li>
                    <li>In the <strong>Settings</strong> tab, scroll down to the <strong>Authorization Requests</strong> section (or <strong>Advanced Settings &rarr; OAuth</strong>).</li>
                    <li>Find <strong>Require Pushed Authorization Requests (PAR)</strong> and toggle it <strong>OFF</strong>.</li>
                    <li>Click <strong>Save Changes</strong> at the bottom of the page.</li>
                </ol>
            </div>
            """
        elif is_api_auth_error:
            guidance_box = f"""
            <div style="background: #fef2f2; border: 1px solid #fecaca; border-radius: 8px; padding: 20px; margin: 20px 0; text-align: left;">
                <h4 style="color: #991b1b; margin-top: 0;">How to Fix in Auth0 Dashboard (1-minute fix):</h4>
                <ol style="color: #7f1d1d; font-size: 14px; line-height: 1.8;">
                    <li>Log in to your <strong>Auth0 Dashboard</strong>.</li>
                    <li>In the left sidebar, click <strong>Applications &rarr; APIs</strong>.</li>
                    <li>Click on <strong>secureHealth API</strong> (Identifier: <code>https://securehealth-api</code>).</li>
                    <li>Click on the <strong>Application Access</strong> (or <em>Machine to Machine Applications</em>) tab, or click the <strong>+ Add Application</strong> button.</li>
                    <li>Find your application (<code>{AUTH0_CLIENT_ID}</code>) and toggle it to <strong>Authorized</strong>.</li>
                    <li>Select scopes (e.g. <code>read:employees</code>) and click <strong>Authorize / Save</strong>.</li>
                </ol>
                <p style="margin-bottom: 0;">
                    <a href="/login?api=false" class="btn" style="background: #0284c7;">Try OIDC-Only Sign-In (Works without API grant)</a>
                </p>
            </div>
            """

        return HTMLResponse(
            f"""
            <!DOCTYPE html>
            <html>
            <head>
                <title>Authentication Error</title>
                {get_base_css()}
            </head>
            <body>
                <div class="card" style="max-width: 700px; margin: 40px auto; border-color: #fca5a5;">
                    <h2 style="color: #b91c1c; margin-top: 0;">Authentication Error during Token Exchange</h2>
                    <pre style="background: #450a0a; color: #fecaca;">{error_msg}</pre>
                    {guidance_box}
                    <div style="margin-top: 20px;">
                        <a href="/" class="btn btn-outline">Back to Home</a>
                    </div>
                </div>
            </body>
            </html>
            """,
            status_code=400,
        )

    userinfo = token.get("userinfo")

    # Explicitly serialize only primitive-type token fields into the session cookie.
    # Authlib returns a Token object that may contain non-serializable types.
    serializable_token = {
        "access_token": token.get("access_token", ""),
        "id_token": token.get("id_token", ""),
        "token_type": token.get("token_type", ""),
        "expires_in": token.get("expires_in", 0),
        "scope": token.get("scope", ""),
    }

    # Serialize userinfo safely (only primitive types)
    serializable_user = {}
    if userinfo:
        for k, v in dict(userinfo).items():
            if isinstance(v, (str, int, float, bool)) or v is None:
                serializable_user[k] = v

    request.session["token"] = serializable_token
    request.session["user"] = serializable_user

    return RedirectResponse(url="/")


@app.get("/debug", response_class=HTMLResponse)
async def debug_session(request: Request):
    """Debug endpoint: shows raw session token contents to verify storage."""
    token_dict = request.session.get("token", {})
    user_dict = request.session.get("user", {})

    access_token = token_dict.get("access_token", "")
    id_token = token_dict.get("id_token", "")

    # Check what kind of token we have
    is_jwt = access_token.count(".") == 2
    token_status = "JWT (correct)" if is_jwt else ("Opaque Token (wrong - needs API audience)" if access_token else "MISSING")

    return HTMLResponse(f"""
    <!DOCTYPE html>
    <html>
    <head><title>Session Debug</title>{get_base_css()}</head>
    <body>
        <div class="card" style="max-width:900px; margin:30px auto;">
            <h2>Session Debug Inspector</h2>
            <table>
                <tr><th>Key</th><th>Value</th></tr>
                <tr><td><strong>Access Token Status</strong></td>
                    <td style="color:{'green' if is_jwt else 'red'}"><strong>{token_status}</strong></td></tr>
                <tr><td><strong>Access Token (first 60 chars)</strong></td>
                    <td><code>{access_token[:60]}...</code></td></tr>
                <tr><td><strong>ID Token present?</strong></td>
                    <td>{"Yes" if id_token else "No"}</td></tr>
                <tr><td><strong>Scope</strong></td>
                    <td><code>{token_dict.get("scope", "NONE")}</code></td></tr>
                <tr><td><strong>User sub</strong></td>
                    <td><code>{user_dict.get("sub", "NONE")}</code></td></tr>
                <tr><td><strong>User email</strong></td>
                    <td>{user_dict.get("email", "NONE")}</td></tr>
            </table>
            <div style="margin-top:20px;">
                <a href="/" class="btn btn-outline">Dashboard</a>
                <a href="/tokens" class="btn btn-outline" style="margin-left:8px;">Token Inspector</a>
                <a href="/call-api" class="btn" style="margin-left:8px;">Call API</a>
            </div>
        </div>
    </body>
    </html>
    """)


@app.get("/tokens", response_class=HTMLResponse)
async def inspect_tokens(request: Request):
    """Token Inspector UI: decodes ID Token and Access Token claims side-by-side."""
    user = request.session.get("user")
    if not user:
        return RedirectResponse(url="/login")

    token_dict = request.session.get("token", {})
    id_token_raw = token_dict.get("id_token", "")
    access_token_raw = token_dict.get("access_token", "")

    id_token_decoded = decode_token_unverified(id_token_raw)
    access_token_decoded = decode_token_unverified(access_token_raw)

    id_claims = id_token_decoded.get("payload", {})
    access_claims = access_token_decoded.get("payload", {})

    return f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Token Inspector — ID Token vs Access Token</title>
        {get_base_css()}
    </head>
    <body>
        <header>
            <div>
                <h1>SecureHealth Token Inspector</h1>
                <span style="font-size: 13px; color: #64748b;">Module 4: JWT Claim Analysis & Token Separation</span>
            </div>
            <div class="nav-links">
                <a href="/">Dashboard</a>
                <a href="/call-api">Call API</a>
                <a href="/logout" style="color: #ef4444;">Logout</a>
            </div>
        </header>

        <div class="card" style="background: #eff6ff; border-color: #bfdbfe;">
            <h3 style="color: #1e40af; margin-top: 0;">Security Principle: ID Token vs Access Token</h3>
            <p style="font-size: 14px; line-height: 1.6; color: #1e3a8a;">
                &bull; <strong>ID Token:</strong> Carries identity claims for the <em>client application</em> (who the user is). Never sent to backend APIs.<br>
                &bull; <strong>Access Token:</strong> Carries authorization proof for the <em>Resource Server / API</em> (audience & scopes). Validated by the API.
            </p>
        </div>

        <div class="grid">
            <div class="card">
                <h3>🪪 ID Token (OIDC Identity)</h3>
                <span class="tag">For Web App Client</span>
                <span class="tag">Audience = Client ID</span>
                
                <h4>Key Claims:</h4>
                <table>
                    <tr><th>Claim</th><th>Value</th><th>Description</th></tr>
                    <tr><td><code>iss</code></td><td><code>{id_claims.get("iss", "N/A")}</code></td><td>Issuer (Auth0 Tenant)</td></tr>
                    <tr><td><code>sub</code></td><td><code>{id_claims.get("sub", "N/A")}</code></td><td>Subject (Unique User ID)</td></tr>
                    <tr><td><code>aud</code></td><td><code>{id_claims.get("aud", "N/A")}</code></td><td>Audience (Matches Client ID)</td></tr>
                    <tr><td><code>exp</code></td><td><code>{id_claims.get("exp", "N/A")}</code></td><td>Token Expiration Timestamp</td></tr>
                    <tr><td><code>iat</code></td><td><code>{id_claims.get("iat", "N/A")}</code></td><td>Issued At Timestamp</td></tr>
                </table>

                <h4>Decoded Payload (JSON):</h4>
                <pre>{json.dumps(id_claims, indent=2)}</pre>
            </div>

            <div class="card">
                <h3>🔑 Access Token (OAuth 2.0 Authorization)</h3>
                <span class="tag">For Protected API</span>
                <span class="tag">Audience = Resource Server</span>

                <h4>Key Claims:</h4>
                <table>
                    <tr><th>Claim</th><th>Value</th><th>Description</th></tr>
                    <tr><td><code>iss</code></td><td><code>{access_claims.get("iss", "N/A")}</code></td><td>Issuer (Auth0 Tenant)</td></tr>
                    <tr><td><code>aud</code></td><td><code>{access_claims.get("aud", "N/A")}</code></td><td>Target API ({AUTH0_AUDIENCE})</td></tr>
                    <tr><td><code>sub</code></td><td><code>{access_claims.get("sub", "N/A")}</code></td><td>Subject (User Identifier)</td></tr>
                    <tr><td><code>scope</code></td><td><code>{access_claims.get("scope", "N/A")}</code></td><td>Granted Scopes / Permissions</td></tr>
                    <tr><td><code>exp</code></td><td><code>{access_claims.get("exp", "N/A")}</code></td><td>Token Expiration Timestamp</td></tr>
                </table>

                <h4>Decoded Payload (JSON):</h4>
                <pre>{json.dumps(access_claims, indent=2)}</pre>
            </div>
        </div>
    </body>
    </html>
    """


@app.get("/call-api", response_class=HTMLResponse)
async def call_protected_api(request: Request):
    """Make a live HTTP call to the SecureHealth Protected API using the stored Access Token."""
    user = request.session.get("user")
    if not user:
        return RedirectResponse(url="/login")

    token_dict = request.session.get("token", {})
    access_token = token_dict.get("access_token", "")

    api_response_status = None
    api_response_body = None
    api_error = None

    if access_token:
        try:
            async with httpx.AsyncClient() as client:
                resp = await client.get(
                    PROTECTED_API_URL,
                    headers={"Authorization": f"Bearer {access_token}"},
                    timeout=5.0,
                )
                api_response_status = resp.status_code
                try:
                    api_response_body = resp.json()
                except Exception:
                    api_response_body = resp.text
        except Exception as e:
            api_error = f"API Server Connection Error: {e}. Is the Protected API running on port 8001?"
    else:
        api_error = "No access token found in current session."

    status_color = "#16a34a" if api_response_status == 200 else "#dc2626"

    return f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>API Call Demo — SecureHealth API</title>
        {get_base_css()}
    </head>
    <body>
        <header>
            <div>
                <h1>API Call Demonstration</h1>
                <span style="font-size: 13px; color: #64748b;">Module 4: Calling Protected API with Bearer Access Token</span>
            </div>
            <div class="nav-links">
                <a href="/">Dashboard</a>
                <a href="/tokens">Token Inspector</a>
                <a href="/logout" style="color: #ef4444;">Logout</a>
            </div>
        </header>

        <div class="card">
            <h3>Request Details</h3>
            <table>
                <tr><td><strong>Target Endpoint</strong></td><td><code>GET {PROTECTED_API_URL}</code></td></tr>
                <tr><td><strong>Authorization Header</strong></td><td><code>Bearer &lt;Access Token Attached&gt;</code></td></tr>
                <tr><td><strong>Required Scope</strong></td><td><code>read:employees</code></td></tr>
            </table>
        </div>

        <div class="card">
            <h3>API Execution Result</h3>
            {"<div style='color: " + status_color + "; font-size: 18px; font-weight: 600;'>HTTP Status: " + str(api_response_status) + "</div>" if api_response_status else ""}
            {"<div style='color: #dc2626; margin-top: 10px; font-weight: 500;'>" + str(api_error) + "</div>" if api_error else ""}

            <h4>Response Payload from Protected Resource:</h4>
            <pre>{json.dumps(api_response_body, indent=2) if isinstance(api_response_body, dict) else str(api_response_body)}</pre>
        </div>

        <div class="card">
            <a href="/call-api" class="btn">Retry Request</a>
            <a href="/" class="btn btn-outline">Back to Dashboard</a>
        </div>
    </body>
    </html>
    """


@app.get("/logout")
async def logout(request: Request):
    """Clear local session and execute Auth0 federated OIDC logout."""
    request.session.clear()
    
    return_to = str(request.base_url)
    logout_url = (
        f"https://{AUTH0_DOMAIN}/v2/logout?"
        + urllib.parse.urlencode({
            "client_id": AUTH0_CLIENT_ID,
            "returnTo": return_to,
        })
    )
    return RedirectResponse(url=logout_url)


if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", "8080"))
    uvicorn.run("webapp.main:app", host="127.0.0.1", port=port, reload=True)