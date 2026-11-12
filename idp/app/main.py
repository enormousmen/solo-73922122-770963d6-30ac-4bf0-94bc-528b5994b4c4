"""Local identity source (IdP) for the portal demo.

Issues one-time authorization codes and exchanges them for RS256 identity
JWTs (sub, sid, iat, exp, purpose="identity").  Also signs logout JWTs
(iat, exp, jti, purpose="logout", unique sid/sub target) and pushes them to
the portal replicas (back-channel logout).

The token endpoint can simulate a slow identity source: `/authorize` accepts
`delay_seconds`, and `/token` then holds the response for that long.  The
identity JWT still carries the iat of the original authorization, so a
logout that lands during the delay correctly invalidates the late login.
"""

from __future__ import annotations

import asyncio
import os
import threading
import time
import uuid

import httpx
import jwt
from cryptography.hazmat.primitives import serialization
from fastapi import FastAPI, HTTPException
from fastapi.responses import PlainTextResponse, RedirectResponse
from pydantic import BaseModel, Field

ISSUER = os.getenv("IDP_ISSUER", "enterprise-idp")
AUDIENCE = os.getenv("IDP_AUDIENCE", "enterprise-portal")
PRIVATE_KEY_PATH = os.getenv("IDP_PRIVATE_KEY_PATH", "/keys/idp_private.pem")
PORTAL_LOGOUT_URLS = [
    url.strip()
    for url in os.getenv("PORTAL_LOGOUT_URLS", "").split(",")
    if url.strip()
]
IDENTITY_TOKEN_TTL = int(os.getenv("IDP_IDENTITY_TOKEN_TTL", "3600"))
LOGOUT_TOKEN_TTL = int(os.getenv("IDP_LOGOUT_TOKEN_TTL", "300"))
CODE_TTL = int(os.getenv("IDP_CODE_TTL", "600"))
MAX_DELAY = float(os.getenv("IDP_MAX_DELAY", "60"))

PRIVATE_KEY = open(PRIVATE_KEY_PATH, "rb").read()
_public_key = serialization.load_pem_private_key(PRIVATE_KEY, password=None).public_key()
PUBLIC_KEY_PEM = _public_key.public_bytes(
    serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
).decode()

app = FastAPI(
    title="Local Identity Provider",
    version="1.0.0",
    description=(
        "Demo identity source. `POST /authorize` issues a code (optionally "
        "with a simulated slow token endpoint), `POST /token` exchanges it "
        "for an RS256 identity JWT (normally called by the portal), and "
        "`POST /logout` pushes a logout JWT to the portal replicas."
    ),
)

# One-time authorization codes.  In-memory on purpose: codes are short-lived
# login attempts; durable state (sessions, logout cutoffs) lives in the
# portal's SQLite database.
_codes: dict[str, dict] = {}
_codes_lock = threading.Lock()


class AuthorizeRequest(BaseModel):
    sub: str = Field(..., json_schema_extra={"examples": ["alice"]})
    sid: str | None = Field(
        default=None,
        description="IdP session id; generated when omitted",
        json_schema_extra={"examples": ["sess-alice-001"]},
    )
    delay_seconds: float = Field(
        default=0, ge=0, le=MAX_DELAY,
        description="Simulated token-endpoint latency (the 'late login response')",
        json_schema_extra={"examples": [8]},
    )


class TokenRequest(BaseModel):
    code: str


class LogoutRequest(BaseModel):
    sub: str | None = Field(default=None, json_schema_extra={"examples": ["alice"]})
    sid: str | None = Field(default=None, json_schema_extra={"examples": ["sess-alice-001"]})
    iat_offset_seconds: int = Field(
        default=0,
        description="Demo aid: backdate the logout iat to emulate an out-of-order notification",
        json_schema_extra={"examples": [0]},
    )


@app.get("/", include_in_schema=False)
def root():
    return RedirectResponse(url="/docs")


@app.get("/healthz", include_in_schema=False)
def healthz():
    return {"status": "ok"}


@app.get("/public-key", response_class=PlainTextResponse, summary="RS256 public key (fixed portal config)")
def public_key():
    return PUBLIC_KEY_PEM


@app.post("/authorize", summary="Issue a one-time authorization code")
async def authorize(body: AuthorizeRequest):
    now = int(time.time())
    code = uuid.uuid4().hex + uuid.uuid4().hex
    record = {
        "sub": body.sub,
        "sid": body.sid or f"sid-{uuid.uuid4().hex[:12]}",
        "iat": now,
        "delay": min(body.delay_seconds, MAX_DELAY),
        "expires_at": now + CODE_TTL,
    }
    with _codes_lock:
        _codes[code] = record
    return {
        "code": code,
        "sub": record["sub"],
        "sid": record["sid"],
        "authorized_at": record["iat"],
        "token_endpoint_delay_seconds": record["delay"],
        "next": "POST the code to the portal's /login (it exchanges it here for you)",
    }


@app.post("/token", summary="Exchange a code for an RS256 identity JWT")
async def token(body: TokenRequest):
    with _codes_lock:
        record = _codes.pop(body.code, None)  # one-time use
    if record is None or record["expires_at"] < time.time():
        raise HTTPException(status_code=401, detail="invalid or expired authorization code")
    if record["delay"] > 0:
        # Simulated slow identity source.  asyncio.sleep keeps this process
        # responsive; the *response* is simply late.  The JWT still carries
        # the original authorization time as iat.
        await asyncio.sleep(record["delay"])
    claims = {
        "iss": ISSUER,
        "aud": AUDIENCE,
        "purpose": "identity",
        "sub": record["sub"],
        "sid": record["sid"],
        "iat": record["iat"],
        "exp": record["iat"] + IDENTITY_TOKEN_TTL,
        "jti": uuid.uuid4().hex,
    }
    id_token = jwt.encode(claims, PRIVATE_KEY, algorithm="RS256")
    return {"id_token": id_token, "token_type": "Bearer", "expires_in": IDENTITY_TOKEN_TTL}


@app.post("/logout", summary="Sign a logout JWT and push it to the portal replicas")
async def logout(body: LogoutRequest):
    if not (body.sub or body.sid):
        raise HTTPException(status_code=400, detail="provide a sub and/or sid target")
    now = int(time.time())
    iat = now + body.iat_offset_seconds
    claims = {
        "iss": ISSUER,
        "aud": AUDIENCE,
        "purpose": "logout",
        "jti": uuid.uuid4().hex,
        "iat": iat,
        "exp": iat + LOGOUT_TOKEN_TTL,
    }
    if body.sub:
        claims["sub"] = body.sub
    if body.sid:
        claims["sid"] = body.sid
    logout_token = jwt.encode(claims, PRIVATE_KEY, algorithm="RS256")

    deliveries = {}
    if PORTAL_LOGOUT_URLS:
        async with httpx.AsyncClient(timeout=10) as client:
            tasks = {
                url: asyncio.create_task(client.post(url, json={"logout_token": logout_token}))
                for url in PORTAL_LOGOUT_URLS
            }
            for url, task in tasks.items():
                try:
                    resp = await task
                    try:
                        payload = resp.json()
                    except ValueError:
                        payload = resp.text[:200]
                    deliveries[url] = {"status_code": resp.status_code, "response": payload}
                except httpx.HTTPError as exc:
                    deliveries[url] = {"error": str(exc)}
    return {"logout_token": logout_token, "claims": claims, "deliveries": deliveries}
