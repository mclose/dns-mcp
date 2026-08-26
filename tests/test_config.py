"""Tests for dns_mcp.config.Settings.

Settings reads from environment + .env, requires three URLs/secret, and
ignores unrelated extras (legacy or future env keys must not crash startup).
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from dns_mcp.config import Settings
from tests.conftest import TEST_POCKET_ID, TEST_SERVER_URL


def _env_with(**overrides) -> dict[str, str]:
    base = {
        "POCKET_ID_BASE_URL": TEST_POCKET_ID,
        "SERVER_URL": TEST_SERVER_URL,
    }
    base.update({k: str(v) for k, v in overrides.items()})
    return base


def _build(monkeypatch: pytest.MonkeyPatch, env: dict[str, str]) -> Settings:
    """Build a Settings instance from the given env, bypassing .env.

    Pydantic-settings reads .env from cwd, which would leak Matthew's local
    state into the test. `_env_file=None` disables file loading for this
    instance only.
    """
    for k in ("POCKET_ID_BASE_URL", "SERVER_URL"):
        monkeypatch.delenv(k, raising=False)
    for k, v in env.items():
        monkeypatch.setenv(k, v)
    return Settings(_env_file=None)


def test_loads_with_all_required_env(monkeypatch: pytest.MonkeyPatch) -> None:
    s = _build(monkeypatch, _env_with())
    assert str(s.pocket_id_base_url).rstrip("/") == TEST_POCKET_ID
    assert str(s.server_url).rstrip("/") == TEST_SERVER_URL


def test_missing_pocket_id_url_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    env = _env_with()
    del env["POCKET_ID_BASE_URL"]
    with pytest.raises(ValidationError, match="pocket_id_base_url"):
        _build(monkeypatch, env)


def test_missing_server_url_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    env = _env_with()
    del env["SERVER_URL"]
    with pytest.raises(ValidationError, match="server_url"):
        _build(monkeypatch, env)


def test_malformed_url_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    with pytest.raises(ValidationError):
        _build(monkeypatch, _env_with(POCKET_ID_BASE_URL="not-a-url"))


def test_extras_ignored(monkeypatch: pytest.MonkeyPatch) -> None:
    """Legacy or unrelated env vars must not crash Settings construction.

    The pre-2.0 .env still has MCP_BEARER_TOKEN, MCP_PORT, etc. on some
    machines. extra='ignore' in model_config keeps the server bootable.
    """
    s = _build(
        monkeypatch,
        _env_with(
            MCP_BEARER_TOKEN="legacy-token",
            MCP_PORT="8083",
            PROXY_PORT="8082",
            LOG_PATH="/var/log/legacy",
            SOMETHING_NEW="future-key",
        ),
    )
    assert str(s.pocket_id_base_url).rstrip("/") == TEST_POCKET_ID.rstrip("/")
