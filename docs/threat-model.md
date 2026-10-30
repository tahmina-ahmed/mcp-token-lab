# Threat model

Scope: the token path between an AI agent, an MCP-style gateway, and the tool servers behind it. This is a model of a common architecture, not of any specific product.

## Assets

- Data and actions behind the tools (here: reading and deleting files).
- User tokens and the downstream tokens derived from them.
- The authorization server's signing key.

## Actors and trust

| Actor | Trust |
|-------|-------|
| User | Trusted principal. Delegates a limited set of scopes to the agent. |
| Agent | **Untrusted by assumption.** It follows instructions found in content it reads, so it can be hijacked. |
| Gateway | Trusted. Authenticates callers, authorizes each tool call, mints downstream tokens. |
| Authorization server | Trusted. Pinned by the gateway and tool servers. |
| First-party tool server (files) | Trusted to enforce its own audience and scope. |
| Third-party tool server (weather) | **Untrusted.** Assumed to log, leak or replay anything it receives. |
| Other authorization servers | Untrusted. An attacker can run one. |

## Trust boundaries

1. Agent to gateway: the only place the user's token is presented.
2. Gateway to each tool server: a separate token per server. The user's token never crosses this line in the hardened design.
3. Gateway to authorization server: token exchange (RFC 8693).

## Attacker model

The attacker can hijack the agent, run a hostile tool server, run their own authorization server, and obtain tokens that were legitimately issued for other services. The attacker cannot read the signing key or modify the gateway's code.

## Threats and where they are covered

| Threat | Covered by |
|--------|-----------|
| Token issued for service A accepted by service B (audience confusion) | Audience checks on every hop |
| Token from an attacker's issuer accepted (issuer mix-up) | Issuer and key pinning |
| Hostile server captures and replays the user's token (passthrough) | Token exchange to a single audience and scope |
| Agent obtains broader scopes through exchange or re-delegation | Subset rule and delegation depth cap |
| Agent calls tools it was never meant to use (confused deputy) | Cedar per-tool policy, human approval for destructive tools |
| Forged or expired tokens | Pinned algorithm, required `exp` |

## Out of scope or not mitigated

- Prompt injection and tool-description poisoning (the agent itself being steered).
- Stolen bearer tokens used before expiry (no DPoP or mTLS binding).
- Revocation, key rotation, and workload identity between services (for example SPIFFE).
- Denial of service, logging and detection, and multi-tenant isolation.
