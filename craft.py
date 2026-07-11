"""CRAFT MCP client — a thin, reusable wrapper around the Emergence CRAFT server.

Reuses the OAuth 2.1 + PKCE plumbing from the official `mcp_starter.py` (the
`em-runtime-mcp` fixed public client, token cached to disk). Exposes a persistent
authenticated session with a generic `call()` plus an `execute_query()` helper
that transparently pages the first chunk of rows back inline.

First run opens a browser once for SSO; the token caches under
~/.cache/em-talk2data/ so later runs are silent.
"""

from __future__ import annotations

import asyncio
import json
import os
import sys
import threading
import webbrowser
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlparse

from mcp.client.auth import OAuthClientProvider, TokenStorage
from mcp.client.session import ClientSession
from mcp.client.streamable_http import streamablehttp_client
from mcp.shared.auth import (
    OAuthClientInformationFull,
    OAuthClientMetadata,
    OAuthToken,
)

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
MCP_URL: str = os.environ.get("CRAFT_MCP_URL", "https://nebius.emergence.ai/mcp")
PROJECT_ID: str = os.environ.get(
    "PROJECT_ID", "f9780007-934d-4e80-b043-d3b825901b73"
)

OAUTH_CLIENT_ID: str = "em-runtime-mcp"
OAUTH_SCOPES: str = "openid profile email organization"
CALLBACK_PORT: int = 9876
CALLBACK_PATH: str = "/callback"
TOKEN_CACHE: Path = Path.home() / ".cache" / "em-talk2data" / "mcp-starter.json"


# ---------------------------------------------------------------------------
# OAuth plumbing (lifted from mcp_starter.py — proven, leave as-is)
# ---------------------------------------------------------------------------
class FileTokenStorage(TokenStorage):
    """Persists OAuth tokens to a 0600 JSON file and pre-seeds the fixed client."""

    def __init__(self, cache_path: Path, client_metadata: OAuthClientMetadata) -> None:
        self._cache_path = cache_path
        self._client_metadata = client_metadata

    async def get_tokens(self) -> OAuthToken | None:
        if not self._cache_path.exists():
            return None
        return OAuthToken.model_validate_json(self._cache_path.read_text())

    async def set_tokens(self, tokens: OAuthToken) -> None:
        self._cache_path.parent.mkdir(parents=True, exist_ok=True)
        self._cache_path.write_text(tokens.model_dump_json())
        self._cache_path.chmod(0o600)

    async def get_client_info(self) -> OAuthClientInformationFull:
        return OAuthClientInformationFull(
            client_id=OAUTH_CLIENT_ID,
            redirect_uris=self._client_metadata.redirect_uris,
            token_endpoint_auth_method="none",
            grant_types=["authorization_code", "refresh_token"],
            response_types=["code"],
            scope=self._client_metadata.scope,
        )

    async def set_client_info(self, client_info: OAuthClientInformationFull) -> None:
        return None


async def _open_browser_for_login(authorization_url: str) -> None:
    print(f"\nOpening browser for SSO login:\n  {authorization_url}\n", file=sys.stderr)
    print("If no browser opens, paste the URL above manually.", file=sys.stderr)
    webbrowser.open(authorization_url)


async def _wait_for_callback() -> tuple[str, str | None]:
    captured: dict[str, str] = {}
    done = threading.Event()

    class _Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802
            query = parse_qs(urlparse(self.path).query)
            if "code" in query:
                captured["code"] = query["code"][0]
                captured["state"] = query.get("state", [""])[0]
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(
                b"<html><body>Login complete. Return to your terminal.</body></html>"
            )
            done.set()

        def log_message(self, *_args: object) -> None:
            return None

    server = HTTPServer(("localhost", CALLBACK_PORT), _Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        await asyncio.to_thread(done.wait)
    finally:
        server.shutdown()

    if "code" not in captured:
        raise RuntimeError("OAuth callback did not include an authorization code")
    state = captured["state"]
    return captured["code"], (state if state else None)


def _build_provider() -> OAuthClientProvider:
    client_metadata = OAuthClientMetadata(
        client_name="scam-token-detector",
        redirect_uris=[f"http://localhost:{CALLBACK_PORT}{CALLBACK_PATH}"],
        grant_types=["authorization_code", "refresh_token"],
        response_types=["code"],
        token_endpoint_auth_method="none",
        scope=OAUTH_SCOPES,
    )
    return OAuthClientProvider(
        server_url=MCP_URL,
        client_metadata=client_metadata,
        storage=FileTokenStorage(TOKEN_CACHE, client_metadata),
        redirect_handler=_open_browser_for_login,
        callback_handler=_wait_for_callback,
    )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _structured(result: Any) -> Any:
    """Return the tool's structured JSON payload, falling back to flattened text."""
    if getattr(result, "structuredContent", None) is not None:
        return result.structuredContent
    parts: list[str] = []
    for item in result.content or []:
        text = getattr(item, "text", None)
        parts.append(text if text is not None else repr(item))
    joined = "\n".join(parts)
    try:
        return json.loads(joined)
    except Exception:
        return {"raw": joined}


def _deep_find(obj: Any, key: str) -> Any:
    """Depth-first search for the first value under `key` anywhere in a nested dict/list."""
    if isinstance(obj, dict):
        if key in obj:
            return obj[key]
        for v in obj.values():
            found = _deep_find(v, key)
            if found is not None:
                return found
    elif isinstance(obj, list):
        for v in obj:
            found = _deep_find(v, key)
            if found is not None:
                return found
    return None


# ---------------------------------------------------------------------------
# Client
# ---------------------------------------------------------------------------
class Craft:
    """Persistent authenticated CRAFT session. Use as an async context manager."""

    def __init__(self, project_id: str = PROJECT_ID) -> None:
        self.project_id = project_id
        self._http_cm = None
        self._session_cm = None
        self.session: ClientSession | None = None

    async def __aenter__(self) -> "Craft":
        provider = _build_provider()
        headers = {"X-Project-ID": self.project_id}
        self._http_cm = streamablehttp_client(MCP_URL, auth=provider, headers=headers)
        read_stream, write_stream, _ = await self._http_cm.__aenter__()
        self._session_cm = ClientSession(read_stream, write_stream)
        self.session = await self._session_cm.__aenter__()
        await self.session.initialize()
        return self

    async def __aexit__(self, *exc: object) -> None:
        if self._session_cm is not None:
            await self._session_cm.__aexit__(*exc)
        if self._http_cm is not None:
            await self._http_cm.__aexit__(*exc)

    async def call(self, tool: str, arguments: dict[str, Any] | None = None) -> Any:
        """Call any CRAFT tool by name, return its structured JSON payload."""
        assert self.session is not None, "Craft session not open"
        result = await self.session.call_tool(tool, arguments or {})
        payload = _structured(result)
        if getattr(result, "isError", False):
            return {"ok": False, "error": payload}
        return payload

    async def execute_query(
        self, connection: str, sql: str, max_rows: int = 200
    ) -> dict[str, Any]:
        """Run SQL and eagerly return the first page of rows inline.

        Wraps execute_query + get_result_page so the agent gets rows in one call.
        """
        run = await self.call(
            "execute_query",
            {"connection": connection, "sql": sql, "max_rows": max_rows},
        )
        artifact = _deep_find(run, "artifact_fqn")
        row_count = _deep_find(run, "row_count")
        if not artifact:
            # No artifact (error or inline result) — hand back whatever we got.
            return {"ok": _deep_find(run, "ok") is not False, "raw": run}
        page = await self.call(
            "get_result_page",
            {"artifact_fqn": artifact, "limit": min(max_rows, 200), "offset": 0},
        )
        columns = _deep_find(page, "columns")
        rows = _deep_find(page, "rows")
        # Occasionally the first page comes back empty even though row_count > 0.
        # Retry once before giving up so the agent doesn't wrongly conclude "no data".
        if (rows is None or rows == []) and row_count:
            page = await self.call(
                "get_result_page",
                {"artifact_fqn": artifact, "limit": min(max_rows, 200), "offset": 0},
            )
            columns = _deep_find(page, "columns") or columns
            rows = _deep_find(page, "rows")
        return {
            "ok": True,
            "row_count": row_count,
            "columns": columns,
            "rows": rows,
            "note": (
                None
                if rows
                else f"row_count={row_count} but page returned no rows; "
                "the data exists — simplify the query (avoid huge columns like bytecode)."
            ),
        }


# Convenience for a quick connectivity check (no LLM needed).
async def _check() -> None:
    async with Craft() as craft:
        hello = await craft.call("hello_world")
        print("hello_world:", json.dumps(hello, default=str))
        conns = await craft.call("list_data_connections")
        slugs = [c.get("slug") for c in (_deep_find(conns, "connections") or [])]
        print("connections:", slugs)


if __name__ == "__main__":
    asyncio.run(_check())
