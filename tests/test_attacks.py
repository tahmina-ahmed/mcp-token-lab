"""Each attack runs against the naive setup (it works) and the hardened one (it is blocked).

The *_hardened tests are the regression tests: if one starts failing, a fix was undone.
"""

import jwt
import pytest

from mcp_token_lab.auth_server import AuthServer
from mcp_token_lab.errors import AuthError, PolicyDenied
from mcp_token_lab.tokens import verify

from conftest import claims_of

READ = {"path": "report.txt"}
DELETE = {"path": "notes.txt"}


# 1. Audience confusion --------------------------------------------------------------------------
# A token legitimately issued for a different service (mail-api) is replayed at the gateway.


def test_audience_confusion_naive_accepts_token_meant_for_another_service(naive):
    token = naive.idp.issue("alice", "mail-api", ["files:read"], "mail-client")
    assert naive.gateway.handle(token, "read_file", READ) == "q3 numbers"


def test_audience_confusion_hardened_rejects_wrong_audience(hardened):
    token = hardened.idp.issue("alice", "mail-api", ["files:read"], "mail-client")
    with pytest.raises(AuthError, match="audience"):
        hardened.gateway.handle(token, "read_file", READ)


# 2. Issuer mix-up -------------------------------------------------------------------------------
# An attacker-run authorization server mints a perfectly valid token with the gateway's audience.


def test_issuer_mixup_naive_trusts_attacker_issuer(naive):
    token = naive.evil_idp.issue("alice", "mcp-gateway", ["files:write"], "evil-client")
    assert naive.gateway.handle(token, "delete_file", DELETE) == "deleted"
    assert "notes.txt" not in naive.files.files


def test_issuer_mixup_hardened_pins_issuer(hardened):
    token = hardened.evil_idp.issue("alice", "mcp-gateway", ["files:write"], "evil-client")
    with pytest.raises(AuthError, match="unknown issuer"):
        hardened.gateway.handle(token, "delete_file", DELETE)
    assert "notes.txt" in hardened.files.files


# 3. Token passthrough ---------------------------------------------------------------------------
# A hostile third-party tool server captures the token it is handed and replays it elsewhere.


def _user_token(idp):
    return idp.issue(
        "alice", "mcp-gateway", ["files:read", "files:write", "weather:read"], "agent-1"
    )


def test_passthrough_naive_lets_hostile_server_replay_the_users_token(naive):
    token = _user_token(naive.idp)
    naive.gateway.handle(token, "get_weather", {})
    stolen = naive.weather.captured_tokens[0]
    assert stolen == token  # the real token went to a third party
    assert naive.files.call(stolen, "delete_file", DELETE) == "deleted"


def test_passthrough_hardened_never_forwards_the_users_token(hardened):
    token = _user_token(hardened.idp)
    hardened.gateway.handle(token, "get_weather", {})
    stolen = hardened.weather.captured_tokens[0]
    assert stolen != token
    claims = claims_of(stolen)
    assert claims["aud"] == "weather-api" and claims["scope"] == "weather:read"
    with pytest.raises(AuthError, match="audience"):
        hardened.files.call(stolen, "delete_file", DELETE)
    assert "notes.txt" in hardened.files.files


# 4. Scope escalation and delegation depth in token exchange (RFC 8693) --------------------------


def test_exchange_naive_grants_scopes_the_subject_never_had():
    sloppy = AuthServer("https://idp.sloppy", strict_exchange=False)
    read_only = sloppy.issue("alice", "mcp-gateway", ["files:read"], "agent-1")
    exchanged = sloppy.exchange(read_only, "files-api", ["files:write"], actor="agent-2")
    assert "files:write" in claims_of(exchanged)["scope"].split()


def test_exchange_hardened_refuses_scope_escalation(idp):
    read_only = idp.issue("alice", "mcp-gateway", ["files:read"], "agent-1")
    with pytest.raises(AuthError, match="escalate"):
        idp.exchange(read_only, "files-api", ["files:write"], actor="agent-2")


def _chain(server, links):
    token = server.issue("alice", "mcp-gateway", ["files:read"], "agent-0")
    for i in range(links):
        token = server.exchange(token, "mcp-gateway", ["files:read"], actor=f"agent-{i + 1}")
    return token


def test_delegation_depth_naive_allows_unbounded_chains():
    sloppy = AuthServer("https://idp.sloppy", strict_exchange=False)
    assert claims_of(_chain(sloppy, 5))["act"]


def test_delegation_depth_hardened_caps_the_chain(idp):
    _chain(idp, 2)  # two hops are fine
    with pytest.raises(AuthError, match="too deep"):
        _chain(idp, 3)


# 5. Per-tool authorization (confused deputy) ----------------------------------------------------
# A compromised agent holding a read-only token asks the gateway to call a destructive tool.


def test_tool_authz_naive_any_valid_token_can_call_any_tool(naive):
    token = naive.idp.issue("alice", "mcp-gateway", ["files:read"], "agent-1")
    assert naive.gateway.handle(token, "delete_file", DELETE) == "deleted"


def test_tool_authz_hardened_cedar_denies_missing_scope(hardened):
    token = hardened.idp.issue("alice", "mcp-gateway", ["files:read"], "agent-1")
    with pytest.raises(PolicyDenied):
        hardened.gateway.handle(token, "delete_file", DELETE)
    assert "notes.txt" in hardened.files.files


def test_tool_authz_hardened_destructive_tools_need_human_approval(hardened):
    token = hardened.idp.issue("alice", "mcp-gateway", ["files:read", "files:write"], "agent-1")
    with pytest.raises(PolicyDenied):  # has the scope, but no approval
        hardened.gateway.handle(token, "delete_file", DELETE)
    assert hardened.gateway.handle(token, "delete_file", DELETE, human_approved=True) == "deleted"


# 6. Token hygiene -------------------------------------------------------------------------------


def test_expired_token_is_rejected(hardened):
    token = hardened.idp.issue("alice", "mcp-gateway", ["files:read"], "agent-1", ttl=-10)
    with pytest.raises(AuthError):
        hardened.gateway.handle(token, "read_file", READ)


def test_alg_none_token_is_rejected(idp):
    forged = jwt.encode(
        {"iss": idp.issuer, "sub": "alice", "aud": "mcp-gateway", "exp": 9999999999},
        key=None,
        algorithm="none",
    )
    with pytest.raises(AuthError):
        verify(forged, lambda iss: idp.public_key, audience="mcp-gateway")


# 7. Known limits: what the hardened setup does NOT stop ----------------------------------------
# These pass today because the behaviour is real. They document residual risk rather than hide it.


def test_known_limit_stolen_bearer_token_replays_until_expiry(hardened):
    """No sender-constraining (e.g. DPoP): whoever holds the token can use it until it expires."""
    token = hardened.idp.issue("alice", "mcp-gateway", ["files:read"], "agent-1")
    # An attacker who exfiltrated the token from the agent's memory or logs:
    assert hardened.gateway.handle(token, "read_file", READ) == "q3 numbers"


def test_known_limit_compromised_agent_reads_everything_in_its_scope(hardened):
    """Policy checks scope, not intent: a hijacked agent can read every file its token covers."""
    token = hardened.idp.issue("alice", "mcp-gateway", ["files:read"], "agent-1")
    leaked = [hardened.gateway.handle(token, "read_file", {"path": p}) for p in hardened.files.files]
    assert leaked == ["q3 numbers", "internal notes"]
