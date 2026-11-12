"""JWT verification for the two token types the portal accepts.

Both token types are RS256 JWTs from the attached identity source and are
verified against the fixed public key, issuer and audience.  Every token
must also carry the expected ``purpose`` claim and be within its validity
window (exp/iat checked, with a small clock leeway).

* identity JWT: sub, sid, iat, exp, purpose="identity"  (login)
* logout JWT:   iat, exp, jti, purpose="logout", plus a unique target
  (sid and/or sub)                                       (back-channel logout)
"""

from __future__ import annotations

import time

import jwt
from fastapi import HTTPException

from . import config

PURPOSE_IDENTITY = "identity"
PURPOSE_LOGOUT = "logout"


def _decode(token: str, expected_purpose: str, error_status: int) -> dict:
    if not token:
        raise HTTPException(status_code=error_status, detail="missing token")
    try:
        claims = jwt.decode(
            token,
            config.PUBLIC_KEY,
            algorithms=["RS256"],
            issuer=config.ISSUER,
            audience=config.AUDIENCE,
            leeway=config.CLOCK_LEEWAY,
            options={"require": ["exp", "iat", "iss", "aud", "purpose"]},
        )
    except jwt.PyJWTError as exc:
        raise HTTPException(
            status_code=error_status, detail=f"token verification failed: {exc}"
        ) from exc
    if claims.get("purpose") != expected_purpose:
        raise HTTPException(
            status_code=error_status,
            detail=f"unexpected token purpose: {claims.get('purpose')!r}",
        )
    if int(claims["iat"]) > int(time.time()) + config.CLOCK_LEEWAY:
        raise HTTPException(status_code=error_status, detail="token iat is in the future")
    return claims


def verify_identity_token(token: str) -> dict:
    """Validate an identity JWT from the token exchange; return its claims."""
    claims = _decode(token, PURPOSE_IDENTITY, error_status=401)
    missing = [name for name in ("sub", "sid") if not claims.get(name)]
    if missing:
        raise HTTPException(status_code=401, detail=f"identity token missing claims: {missing}")
    return claims


def verify_logout_token(token: str) -> dict:
    """Validate a back-channel logout JWT; return its claims."""
    claims = _decode(token, PURPOSE_LOGOUT, error_status=400)
    if not claims.get("jti"):
        raise HTTPException(status_code=400, detail="logout token missing jti")
    if not (claims.get("sid") or claims.get("sub")):
        raise HTTPException(
            status_code=400, detail="logout token must carry a unique sid or sub target"
        )
    return claims
