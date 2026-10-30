"""MCP-style gateways: one naive, one hardened. Same interface, so tests run against both."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import cedarpy

from .auth_server import AuthServer
from .errors import AuthError, PolicyDenied
from .tokens import KeyResolver, verify
from .tool_servers import ToolServer

GATEWAY_AUDIENCE = "mcp-gateway"
POLICY_PATH = Path(__file__).with_name("policy.cedar")


@dataclass(frozen=True)
class Tool:
    name: str
    server: ToolServer
    required_scope: str
    destructive: bool = False


class NaiveGateway:
    """Common mistakes, all in one place:

    - trusts any issuer it can resolve a key for (issuer mix-up)
    - never checks the token's audience (audience confusion)
    - any valid token may call any tool (no per-tool authorization)
    - forwards the caller's own token to the downstream server (token passthrough)
    """

    def __init__(self, key_resolver: KeyResolver, tools: list[Tool]):
        self.key_resolver = key_resolver
        self.tools = {t.name: t for t in tools}

    def authenticate(self, token: str) -> dict:
        return verify(token, self.key_resolver, check_audience=False)

    def handle(self, token: str, tool: str, args: dict, human_approved: bool = False) -> str:
        self.authenticate(token)
        return self.tools[tool].server.call(token, tool, args)  # passthrough


class HardenedGateway:
    """Fixes, each tied to a test in tests/:

    - pins the issuer and its key
    - requires the token to be aimed at this gateway
    - authorizes every tool call with a Cedar policy
    - never forwards the caller's token; exchanges it for a narrow, single-audience one (RFC 8693)
    """

    def __init__(self, idp: AuthServer, tools: list[Tool], client_id: str = "mcp-gateway-client"):
        self.idp = idp
        self.client_id = client_id
        self.tools = {t.name: t for t in tools}
        self.policy = POLICY_PATH.read_text()
        self._resolver: KeyResolver = lambda iss: idp.public_key if iss == idp.issuer else None

    def authenticate(self, token: str) -> dict:
        return verify(token, self._resolver, audience=GATEWAY_AUDIENCE, check_audience=True)

    def _authorize(self, claims: dict, tool: Tool, human_approved: bool) -> None:
        entities = [
            {
                "uid": {"type": "Tool", "id": tool.name},
                "attrs": {
                    "required_scope": tool.required_scope,
                    "destructive": tool.destructive,
                },
                "parents": [],
            }
        ]
        request = {
            "principal": f'Agent::"{claims["client_id"]}"',
            "action": 'Action::"CallTool"',
            "resource": f'Tool::"{tool.name}"',
            "context": {
                "scopes": claims.get("scope", "").split(),
                "human_approved": human_approved,
            },
        }
        if not cedarpy.is_authorized(request, self.policy, entities).allowed:
            raise PolicyDenied(f"{tool.name} denied by policy")

    def handle(self, token: str, tool: str, args: dict, human_approved: bool = False) -> str:
        claims = self.authenticate(token)
        spec = self.tools[tool]
        self._authorize(claims, spec, human_approved)
        downstream_token = self.idp.exchange(
            subject_token=token,
            audience=spec.server.audience,
            scopes=[spec.required_scope],
            actor=self.client_id,
        )
        return spec.server.call(downstream_token, tool, args)
