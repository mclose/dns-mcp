"""Tests for the dynamic prompts/*.txt registration.

Tool registration count and per-prompt body assertions live in
test_server.py — those cover the normal case (5 .txt files load 5 prompts).
This file covers the empty-directory fallback: if prompts/ is missing or
empty, create_server() should still succeed and register zero prompts.
"""

from __future__ import annotations

import pytest

from dns_mcp import server as server_mod


@pytest.fixture
def empty_prompts_dir(tmp_path, monkeypatch: pytest.MonkeyPatch):
    """Repoint _PROMPTS_DIR at an empty directory."""
    monkeypatch.setattr(server_mod, "_PROMPTS_DIR", tmp_path)
    return tmp_path


async def test_empty_prompts_dir_registers_zero(empty_prompts_dir):
    app = server_mod.create_server()
    prompts = await app.list_prompts()
    assert prompts == []


async def test_missing_prompts_dir_does_not_crash(monkeypatch: pytest.MonkeyPatch, tmp_path):
    """A non-existent _PROMPTS_DIR path must be tolerated."""
    nonexistent = tmp_path / "does-not-exist"
    monkeypatch.setattr(server_mod, "_PROMPTS_DIR", nonexistent)

    app = server_mod.create_server()
    prompts = await app.list_prompts()
    assert prompts == []
