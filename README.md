# mcp-token-lab

A small, local lab for attacking and fixing the token path an AI agent uses to call MCP-style tools.

It models one gateway sitting between an agent and several tool servers, in two versions:

- **Naive:** the shortcuts that show up in real agent and MCP deployments.
- **Hardened:** the same system with each shortcut fixed.

Every attack is a test. It succeeds against the naive version and fails against the hardened one. The hardened tests stay in CI as regression tests.

> This is a learning and demo project: toy code, in-process, no network, no real services. It is not a security product, and nothing here targets any real system.

```bash
pip install -r requirements.txt
pytest -q          # 17 tests
```

## The system being attacked

```
agent ──user token (aud=mcp-gateway)──▶ gateway ──▶ files server   (read_file, delete_file)
                                           └──────▶ weather server (third party, treated as hostile)
authorization server (issues tokens, RFC 8693 token exchange)
```

Trust boundaries, assets and attacker assumptions are in [docs/threat-model.md](docs/threat-model.md). The main assumption is that **the agent can be compromised** (for example by prompt injection), so the question is what a compromised agent can still do.

## Attacks and fixes

| # | Attack | Naive behavior | Hardened fix | Tests |
|---|--------|----------------|--------------|-------|
| 1 | **Audience confusion:** replay a token issued for another service | Gateway checks the signature only, so the token is accepted | Require `aud` to match the gateway on every hop | `test_audience_confusion_*` |
| 2 | **Issuer mix-up:** attacker-run authorization server mints a valid-looking token | Gateway trusts any issuer it can find a key for | Pin the issuer and its key | `test_issuer_mixup_*` |
| 3 | **Token passthrough:** hostile tool server captures the forwarded token and replays it elsewhere | The user's own token is forwarded downstream and works everywhere | Never forward it. Exchange it (RFC 8693) for a single-audience, single-scope token per downstream | `test_passthrough_*` |
| 4 | **Scope escalation and deep delegation** in token exchange | Exchange grants whatever is asked, with unbounded `act` chains | Requested scopes must be a subset of the subject's. Cap delegation depth at 2 | `test_exchange_*`, `test_delegation_depth_*` |
| 5 | **Confused deputy:** a read-only agent asks the gateway to call a destructive tool | Any valid token can call any tool | Per-tool authorization with a [Cedar policy](mcp_token_lab/policy.cedar). Destructive tools also need human approval | `test_tool_authz_*` |
| 6 | **Token hygiene:** expired tokens and `alg=none` | | Pinned algorithm (RS256), required `exp` | `test_expired_*`, `test_alg_none_*` |

I checked that the hardened tests fail when their fix is removed, one fix at a time: the audience check, the issuer pin, the Cedar check, the passthrough fix, and the exchange scope check. Each removal made its test fail.

## What a compromised agent can still do (hardened version)

This is the honest part. The hardened setup narrows the damage, and does not remove it:

- **Everything inside its granted scope, until the token expires.** Cedar checks scope, not intent. A hijacked agent holding `files:read` can read every file ([`test_known_limit_compromised_agent_reads_everything_in_its_scope`](tests/test_attacks.py)).
- **Replay a stolen token.** Tokens are bearer tokens with no sender-constraining (such as DPoP), so whoever steals one can use it until it expires ([`test_known_limit_stolen_bearer_token_replays_until_expiry`](tests/test_attacks.py)).
- **Anything this lab does not model:** prompt injection and poisoned tool descriptions that steer the agent itself, workload identity and PKI between services (for example SPIFFE), token revocation, and key rotation.

## Design notes

- **Pinned algorithm.** Verification only accepts `RS256` and never lets the token choose.
- **Tokens narrow at every hop.** A downstream server sees a token minted for it alone, with only the scope that call needs.
- **Policy is data.** Authorization lives in one reviewable file, so changes can be diffed and tested like code.
- **Naive and hardened share code.** Both are built from the same classes with different flags, so each test shows the exact difference.

## Layout

```
mcp_token_lab/   auth_server.py  gateway.py  tool_servers.py  tokens.py  policy.cedar
tests/           test_attacks.py  conftest.py
docs/            threat-model.md
```
