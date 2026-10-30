"""A minimal authorization server: issues tokens and performs RFC 8693 token exchange.

`strict_exchange=False` models a server that trusts whatever the caller asks for.
"""

from __future__ import annotations

import time
import uuid
from typing import Optional

import jwt
from cryptography.hazmat.primitives.asymmetric import rsa

from .errors import AuthError

MAX_DELEGATION_DEPTH = 2


class AuthServer:
    def __init__(self, issuer: str, ttl: int = 300, strict_exchange: bool = True):
        self.issuer = issuer
        self.ttl = ttl
        self.strict_exchange = strict_exchange
        self._private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.public_key = self._private_key.public_key()

    def issue(
        self,
        sub: str,
        aud: str,
        scopes: list[str],
        client_id: str,
        act: Optional[dict] = None,
        ttl: Optional[int] = None,
    ) -> str:
        now = int(time.time())
        claims = {
            "iss": self.issuer,
            "sub": sub,
            "aud": aud,
            "scope": " ".join(scopes),
            "client_id": client_id,
            "iat": now,
            "exp": now + (self.ttl if ttl is None else ttl),
            "jti": str(uuid.uuid4()),
        }
        if act:
            claims["act"] = act
        return jwt.encode(claims, self._private_key, algorithm="RS256")

    def exchange(self, subject_token: str, audience: str, scopes: list[str], actor: str) -> str:
        """RFC 8693 token exchange: trade a token for one aimed at `audience` for `actor`."""
        try:
            subject = jwt.decode(
                subject_token,
                self.public_key,
                algorithms=["RS256"],
                options={"verify_aud": False, "require": ["exp", "iss", "sub"]},
                issuer=self.issuer,
            )
        except jwt.PyJWTError as exc:
            raise AuthError(f"subject token rejected: {exc}") from exc

        granted = set(subject.get("scope", "").split())

        if self.strict_exchange:
            extra = set(scopes) - granted
            if extra:
                raise AuthError(f"exchange would escalate scopes: {sorted(extra)}")
            if _depth(subject.get("act")) + 1 > MAX_DELEGATION_DEPTH:
                raise AuthError("delegation chain too deep")

        # `act` records who is acting on behalf of the subject; nested when re-delegated.
        act = {"sub": actor}
        if subject.get("act"):
            act["act"] = subject["act"]

        return self.issue(
            sub=subject["sub"],
            aud=audience,
            scopes=scopes,
            client_id=actor,
            act=act,
            ttl=min(self.ttl, max(1, int(subject["exp"] - time.time()))),
        )


def _depth(act: Optional[dict]) -> int:
    depth = 0
    while act:
        depth += 1
        act = act.get("act")
    return depth
