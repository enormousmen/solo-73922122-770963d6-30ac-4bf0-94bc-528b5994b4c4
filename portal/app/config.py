"""Static configuration for the portal API.

Everything security-relevant (IdP public key, issuer, audience) is fixed
configuration supplied via environment variables / mounted files.  There is
no dynamic key discovery at runtime: tokens are only ever verified against
the configured key, issuer and audience.
"""

import os
from pathlib import Path

# --- Fixed trust configuration -------------------------------------------------
ISSUER = os.getenv("IDP_ISSUER", "enterprise-idp")
AUDIENCE = os.getenv("IDP_AUDIENCE", "enterprise-portal")
PUBLIC_KEY_PATH = os.getenv("IDP_PUBLIC_KEY_PATH", "/keys/idp_public.pem")

# --- Attached local identity source --------------------------------------------
TOKEN_URL = os.getenv("IDP_TOKEN_URL", "http://localhost:9000/token")
# The token exchange may legitimately be slow (this is the "late login
# response" scenario), so the HTTP timeout must be generous.  No database
# lock is held while waiting (see app/main.py).
TOKEN_EXCHANGE_TIMEOUT = float(os.getenv("IDP_TOKEN_EXCHANGE_TIMEOUT", "75"))

# --- Local state ---------------------------------------------------------------
DB_PATH = os.getenv("PORTAL_DB_PATH", "/data/portal.db")

# Tolerated clock skew (seconds) when validating exp/iat.
CLOCK_LEEWAY = int(os.getenv("TOKEN_CLOCK_LEEWAY", "30"))

PUBLIC_KEY = Path(PUBLIC_KEY_PATH).read_text(encoding="utf-8")
