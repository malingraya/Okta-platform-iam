import os
from auth0.management import Auth0

AUTH0_DOMAIN = os.getenv("AUTH0_DOMAIN")
AUTH0_TOKEN = os.getenv("AUTH0_TOKEN")

if not AUTH0_DOMAIN:
    raise RuntimeError("AUTH0_DOMAIN environment variable is not set")

if not AUTH0_TOKEN:
    raise RuntimeError("AUTH0_TOKEN environment variable is not set")

auth0_client = Auth0(
    tenant_domain=AUTH0_DOMAIN,
    token=AUTH0_TOKEN
)