"""A small, local lab for attacking and fixing the token path an AI agent uses to call MCP-style tools.

Everything here is a toy model that runs in-process. It does not talk to any real service.
"""

from .errors import AuthError, PolicyDenied

__all__ = ["AuthError", "PolicyDenied"]
