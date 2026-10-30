class AuthError(Exception):
    """Token failed authentication (signature, issuer, audience, expiry, exchange rules)."""


class PolicyDenied(Exception):
    """Token was valid but the policy engine refused this action."""
