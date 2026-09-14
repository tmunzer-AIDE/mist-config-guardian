"""Bounded Streamable HTTP client for the existing Mist MCP, not a Mist API adapter."""

import json
from contextlib import AbstractAsyncContextManager
from typing import Self
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

import httpx

MAX_WIRE_BYTES = 262_144


class MistMcpError(RuntimeError):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


class MistMcpClient(AbstractAsyncContextManager["MistMcpClient"]):
    def __init__(self, *, url: str, token: str, cloud: str) -> None:
        parts = urlsplit(url)
        if (
            parts.scheme not in {"https", "http"}
            or not parts.hostname
            or parts.username
            or parts.password
            or parts.fragment
        ):
            msg = "invalid_response"
            raise MistMcpError(msg)
        query = dict(parse_qsl(parts.query))
        query["cloud"] = cloud
        self.url = urlunsplit(parts._replace(query=urlencode(query)))
        self._client = httpx.AsyncClient(
            headers={
                "Authorization": f"Bearer {token}",
                "Accept": "application/json, text/event-stream",
                "X-Mist-Base-URL": f"https://{cloud}",
            },
            timeout=20,
            follow_redirects=False,
        )
        self._next_id = 0

    async def __aenter__(self) -> Self:
        try:
            result = await self.rpc(
                "initialize",
                {
                    "protocolVersion": "2025-03-26",
                    "capabilities": {},
                    "clientInfo": {"name": "mist-config-guardian", "version": "1"},
                },
            )
            self._client.headers["MCP-Protocol-Version"] = str(result.get("protocolVersion", "2025-03-26"))
            await self.rpc("notifications/initialized", {}, notification=True)
        except BaseException:
            await self._client.aclose()
            raise
        return self

    async def __aexit__(self, *_args: object) -> None:
        await self._client.aclose()

    async def rpc(self, method: str, params: dict, *, notification: bool = False) -> dict:  # noqa: C901, PLR0912 - JSON/SSE protocol parsing
        self._next_id += 1
        identity = self._next_id
        payload = {"jsonrpc": "2.0", "method": method, "params": params}
        if not notification:
            payload["id"] = identity
        try:
            async with self._client.stream("POST", self.url, json=payload) as response:
                response.raise_for_status()
                if session := response.headers.get("mcp-session-id"):
                    self._client.headers["Mcp-Session-Id"] = session
                if notification and response.status_code in {200, 202, 204}:
                    return {}
                body = bytearray()
                if "text/event-stream" in response.headers.get("content-type", ""):
                    buffer = ""
                    async for chunk in response.aiter_bytes():
                        body.extend(chunk)
                        if len(body) > MAX_WIRE_BYTES:
                            msg = "response_limit"
                            raise MistMcpError(msg)
                        # Decode only complete UTF-8 buffers; event payloads are bounded before parsing.
                        try:
                            buffer = body.decode("utf-8").replace("\r\n", "\n")
                        except UnicodeDecodeError:
                            continue
                        for block in buffer.split("\n\n")[:-1]:
                            event = [line[5:].lstrip() for line in block.splitlines() if line.startswith("data:")]
                            if event:
                                item = json.loads("\n".join(event))
                                if item.get("id") == identity:
                                    return self._result(item)
                    msg = "invalid_response"
                    raise MistMcpError(msg)
                async for part in response.aiter_bytes():
                    body.extend(part)
                    if len(body) > MAX_WIRE_BYTES:
                        msg = "response_limit"
                        raise MistMcpError(msg)
                item = json.loads(body)
                if item.get("id") != identity:
                    msg = "invalid_response"
                    raise MistMcpError(msg)
                return self._result(item)
        except httpx.HTTPError:
            msg = "transport"
            raise MistMcpError(msg) from None
        except (ValueError, AttributeError, TypeError):
            msg = "invalid_response"
            raise MistMcpError(msg) from None

    @staticmethod
    def _result(item: dict) -> dict:
        if "error" in item:
            msg = "tool_error"
            raise MistMcpError(msg)
        result = item.get("result")
        if not isinstance(result, dict):
            msg = "invalid_response"
            raise MistMcpError(msg)
        return result

    async def list_tools(self) -> dict:
        return await self.rpc("tools/list", {})

    async def call_tool(self, name: str, arguments: dict) -> dict:
        return await self.rpc("tools/call", {"name": name, "arguments": arguments})
