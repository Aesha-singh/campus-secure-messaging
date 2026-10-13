"""Client-side mDNS/DNS-SD browser: find CSCP servers on the LAN.

Networking concept demonstrated
-------------------------------
**Service browsing (RFC 6763 §4).**  The client sends a multicast PTR query for
``_cscp._tcp.local.``; every server answers with its instance list.  For each
instance the browser resolves SRV (host + port), TXT (capabilities), and the
A/AAAA address records, yielding a ready-to-dial ``(address, port)`` pair.

This turns "type the server IP" into "pick the server from a list" -- the same
discovery your OS uses for Chromecasts and network printers.  The browser is
asynchronous: it fires a callback as services appear/disappear, which the GUI
uses to repopulate a server picker live.
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Callable
from dataclasses import dataclass, field

from zeroconf import ServiceStateChange
from zeroconf.asyncio import AsyncServiceBrowser, AsyncServiceInfo, AsyncZeroconf

log = logging.getLogger("cscp.client.discovery")


@dataclass(slots=True)
class DiscoveredServer:
    """One resolved CSCP service discovered over mDNS."""

    name: str
    host: str
    port: int
    addresses: list[str] = field(default_factory=list)
    properties: dict[str, str] = field(default_factory=dict)

    @property
    def label(self) -> str:
        instance = self.name.split(".")[0]
        tls = self.properties.get("tls")
        suffix = " (TLS)" if tls == "1" else ""
        return f"{instance} @ {self.host}:{self.port}{suffix}"


def _decode_properties(raw: dict[bytes, bytes | None]) -> dict[str, str]:
    return {
        k.decode("utf-8", "replace"): (v or b"").decode("utf-8", "replace")
        for k, v in raw.items()
        if k is not None
    }


class ServerBrowser:
    """Continuously browse for ``_cscp._tcp`` services and report changes.

    ``on_found`` is called (from the event loop) for every resolved server;
    ``on_lost`` when a service disappears.  Call :meth:`stop` to tear down.
    """

    def __init__(
        self,
        *,
        service_type: str = "_cscp._tcp.local.",
        on_found: Callable[[DiscoveredServer], None] | None = None,
        on_lost: Callable[[str], None] | None = None,
    ) -> None:
        self.service_type = service_type
        self.on_found = on_found
        self.on_lost = on_lost
        self._zc: AsyncZeroconf | None = None
        self._browser: AsyncServiceBrowser | None = None
        self._seen: dict[str, DiscoveredServer] = {}
        self._loop: asyncio.AbstractEventLoop | None = None

    @property
    def servers(self) -> list[DiscoveredServer]:
        return list(self._seen.values())

    async def start(self) -> None:
        self._loop = asyncio.get_running_loop()
        self._zc = AsyncZeroconf()
        self._browser = AsyncServiceBrowser(
            self._zc.zeroconf,
            self.service_type,
            handlers=[self._on_state_change],
        )
        log.info("mdns_browse_started", extra={"service_type": self.service_type})

    async def stop(self) -> None:
        if self._browser is not None:
            await self._browser.async_cancel()
            self._browser = None
        if self._zc is not None:
            await self._zc.async_close()
            self._zc = None
        self._seen.clear()

    async def _resolve(self, name: str) -> DiscoveredServer | None:
        assert self._zc is not None
        info = AsyncServiceInfo(self.service_type, name)
        if not await info.async_request(self._zc.zeroconf, timeout=2000):
            return None
        addresses = info.parsed_scoped_addresses() or info.parsed_addresses()
        if not addresses or info.port is None:
            return None
        return DiscoveredServer(
            name=name,
            host=addresses[0],
            port=info.port,
            addresses=list(addresses),
            properties=_decode_properties(info.properties or {}),
        )

    def _on_state_change(
        self, zeroconf: object, service_type: str, name: str, state_change: ServiceStateChange
    ) -> None:
        # The handler is sync; schedule the async resolve on the running loop.
        if state_change is ServiceStateChange.Removed:
            self._seen.pop(name, None)
            if self.on_lost is not None:
                self.on_lost(name)
            return
        if self._loop is not None and not self._loop.is_closed():
            self._loop.create_task(self._resolve_and_report(name))

    async def _resolve_and_report(self, name: str) -> None:
        server = await self._resolve(name)
        if server is None:
            return
        self._seen[name] = server
        if self.on_found is not None:
            self.on_found(server)


async def discover_servers(
    service_type: str = "_cscp._tcp.local.", timeout: float = 3.0  # noqa: ASYNC109 -- browse window, not a cancel scope
) -> list[DiscoveredServer]:
    """One-shot browse: collect servers for ``timeout`` seconds, then return."""
    found: list[DiscoveredServer] = []

    def _collect(server: DiscoveredServer) -> None:
        if all(s.name != server.name for s in found):
            found.append(server)

    browser = ServerBrowser(service_type=service_type, on_found=_collect)
    await browser.start()
    try:
        await asyncio.sleep(timeout)
    finally:
        await browser.stop()
    return found
