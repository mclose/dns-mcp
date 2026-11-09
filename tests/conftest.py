"""Shared setup for dns-mcp tests.

Env vars are set at conftest import time, BEFORE any `from dns_mcp...` import:
`dns_mcp.config.settings` is built at module import, so the env must exist
first. Direct assignment, not setdefault, so an external env (CI dummies, a
local .env) cannot cause silent mismatches with values tests embed literally.
Tests never hit the real network; auth tests sign tokens locally.
"""

from __future__ import annotations

import os

_TEST_POCKET_ID = "https://id.test.example"
_TEST_SERVER_URL = "https://dns-mcp.test.example"

os.environ["POCKET_ID_BASE_URL"] = _TEST_POCKET_ID
os.environ["SERVER_URL"] = _TEST_SERVER_URL
os.environ["ALLOWED_SUBS"] = "user-123"

TEST_POCKET_ID = _TEST_POCKET_ID
TEST_SERVER_URL = _TEST_SERVER_URL
TEST_RESOURCE = f"{_TEST_SERVER_URL}/mcp"


class ClientApp:
    """The server seen through fastmcp's in-memory Client — what an MCP client
    actually receives (schemas, structured results, validation errors) rather
    than fastmcp's internal objects. Keeps the old `app.call_tool(...)` ->
    (content, structured) shape the tests were written against."""

    def __init__(self, server) -> None:
        self.server = server

    def _client(self):
        from fastmcp import Client

        return Client(self.server)

    async def list_tools(self):
        async with self._client() as c:
            return await c.list_tools()

    async def call_tool(self, name: str, args: dict):
        async with self._client() as c:
            r = await c.call_tool(name, args)
            return r.content, r.structured_content

    async def list_prompts(self):
        async with self._client() as c:
            return await c.list_prompts()

    async def get_prompt(self, name: str, args: dict):
        async with self._client() as c:
            return await c.get_prompt(name, args)

    async def list_resources(self):
        async with self._client() as c:
            return await c.list_resources()
