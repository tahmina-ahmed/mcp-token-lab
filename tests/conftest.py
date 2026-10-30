from __future__ import annotations

from dataclasses import dataclass

import jwt
import pytest

from mcp_token_lab.auth_server import AuthServer
from mcp_token_lab.gateway import HardenedGateway, NaiveGateway, Tool
from mcp_token_lab.tool_servers import FilesServer, UntrustedWeatherServer


@dataclass
class World:
    gateway: object
    files: FilesServer
    weather: UntrustedWeatherServer
    idp: AuthServer
    evil_idp: AuthServer


def _tools(files, weather):
    return [
        Tool("read_file", files, "files:read"),
        Tool("delete_file", files, "files:write", destructive=True),
        Tool("get_weather", weather, "weather:read"),
    ]


@pytest.fixture
def idp():
    return AuthServer("https://idp.example")


@pytest.fixture
def evil_idp():
    return AuthServer("https://evil.example")


@pytest.fixture
def naive(idp, evil_idp):
    """Resolves keys for any issuer it has heard of; no audience or scope checks anywhere."""
    registry = {idp.issuer: idp.public_key, evil_idp.issuer: evil_idp.public_key}
    flags = dict(check_audience=False, check_scope=False)
    files = FilesServer(registry.get, **flags)
    weather = UntrustedWeatherServer(registry.get, **flags)
    return World(NaiveGateway(registry.get, _tools(files, weather)), files, weather, idp, evil_idp)


@pytest.fixture
def hardened(idp, evil_idp):
    """Pinned issuer, audience and scope checks on every hop, Cedar at the gateway, token exchange."""

    def pinned(iss):
        return idp.public_key if iss == idp.issuer else None

    files = FilesServer(pinned)
    weather = UntrustedWeatherServer(pinned)
    return World(HardenedGateway(idp, _tools(files, weather)), files, weather, idp, evil_idp)


def claims_of(token: str) -> dict:
    """Read a token's claims without verifying it (for assertions only)."""
    return jwt.decode(token, options={"verify_signature": False})
