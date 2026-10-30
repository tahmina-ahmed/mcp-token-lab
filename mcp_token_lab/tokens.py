"""Shared JWT verification used by gateways and tool servers."""

from __future__ import annotations

from typing import Callable, Optional

import jwt

from .errors import AuthError

# Maps an `iss` claim to the public key we will use to check the signature, or None if unknown.
KeyResolver = Callable[[Optional[str]], Optional[object]]


def verify(
    token: str,
    key_resolver: KeyResolver,
    audience: Optional[str] = None,
    check_audience: bool = True,
) -> dict:
    """Verify a bearer token and return its claims.

    check_audience=False is deliberately available so the naive implementations can model the bug.
    """
    try:
        unverified = jwt.decode(token, options={"verify_signature": False})
    except jwt.PyJWTError as exc:
        raise AuthError(f"malformed token: {exc}") from exc

    key = key_resolver(unverified.get("iss"))
    if key is None:
        raise AuthError(f"unknown issuer: {unverified.get('iss')!r}")

    try:
        return jwt.decode(
            token,
            key,
            algorithms=["RS256"],  # pinned: never let the token pick its own algorithm
            audience=audience if check_audience else None,
            options={"require": ["exp", "iss", "sub"], "verify_aud": check_audience},
        )
    except jwt.InvalidAudienceError as exc:
        raise AuthError("audience mismatch") from exc
    except jwt.PyJWTError as exc:
        raise AuthError(f"invalid token: {exc}") from exc
