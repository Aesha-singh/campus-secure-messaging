"""mDNS/DNS-SD service advertisement for the CSCP server.

Networking concept demonstrated
-------------------------------
**Zero-configuration service discovery (RFC 6762 / RFC 6763).**  Instead of
hard-coding the server's host and port in every client config, the server
advertises a ``_cscp._tcp.local.`` service over multicast DNS.  A client on the
same LAN browses for that service type and learns the address(es), port, and
TXT metadata without any manual setup -- the same mechanism printers (``_ipp``)
and chat apps (``_presence``) use.

DNS-SD record layout for one service instance:

* **PTR** ``_cscp._tcp.local.`` -> ``Campus CSCP._cscp._tcp.local.`` (which
  instances exist)
* **SRV** ``Campus CSCP._cscp._tcp.local.`` -> ``cscp-campus.local.:9443``
  (target host + port)
* **TXT** ``Campus CSCP._cscp._tcp.local.`` -> key/value properties
  (protocol version, TLS flag, ...)
* **A/AAAA** ``cscp-campus.local.`` -> the server's IPv4/IPv6 address(es)

The advertiser is optional and best-effort: if multicast is unavailable the
server keeps serving unicast TCP normally.
"""

from __future__ import annotations

import logging
import socket
from typing import Any

from zeroconf import ServiceInfo
from zeroconf.asyncio import AsyncZeroconf

log = logging.getLogger("cscp.server.mdns")


def local_addresses(prefer_v4: str | None = None, prefer_v6: str | None = None) -> list[bytes]:
    """Return packed IP addresses to advertise (LAN reachable, not 0.0.0.0).

    Wildcard binds (``0.0.0.0``/``::``) are translated to the host's primary
    interface address so peers on the LAN can actually reach the service.
    """
    packed: list[bytes] = []
    if prefer_v4 and prefer_v4 not in ("0.0.0.0", ""):  # noqa: S104 -- comparison, not a bind
        try:
            packed.append(socket.inet_aton(prefer_v4))
        except OSError:
            pass
    if prefer_v6 and prefer_v6 not in ("::", ""):
        try:
            packed.append(socket.inet_pton(socket.AF_INET6, prefer_v6))
        except OSError:
            pass
    if packed:
        return packed
    # Wildcard bind: discover a routable primary address.
    try:
        host = socket.gethostname()
        for info in socket.getaddrinfo(host, None):
            fam, _, _, _, sockaddr = info
            if fam == socket.AF_INET:
                packed.append(socket.inet_aton(str(sockaddr[0])))
    except OSError:
        pass
    if not packed:  # last resort so the advertiser still has an address
        packed.append(socket.inet_aton("127.0.0.1"))
    return packed


class MdnsAdvertiser:
    """Register/unregister one ``_cscp._tcp`` service via AsyncZeroconf."""

    def __init__(
        self,
        *,
        instance_name: str,
        port: int,
        addresses: list[bytes] | None = None,
        service_type: str = "_cscp._tcp.local.",
        host_name: str = "cscp-campus.local.",
        properties: dict[str, str] | None = None,
    ) -> None:
        self.instance_name = instance_name
        self.port = port
        self.addresses = addresses or [socket.inet_aton("127.0.0.1")]
        self.service_type = service_type
        self.host_name = host_name if host_name.endswith(".") else host_name + "."
        self.properties = properties or {}
        self._zc: AsyncZeroconf | None = None
        self._info: ServiceInfo | None = None

    @property
    def service_name(self) -> str:
        """The DNS-SD instance FQDN, e.g. ``Campus CSCP._cscp._tcp.local.``."""
        return f"{self.instance_name}.{self.service_type}"

    def _build_info(self) -> ServiceInfo:
        return ServiceInfo(
            type_=self.service_type,
            name=self.service_name,
            addresses=self.addresses,
            port=self.port,
            properties=self.properties,
            server=self.host_name,
        )

    async def start(self) -> None:
        """Begin advertising; failures are logged, never fatal to the server."""
        try:
            self._zc = AsyncZeroconf()
            self._info = self._build_info()
            await self._zc.async_register_service(self._info)
            log.info(
                "mdns_advertised",
                extra={"service": self.service_name, "port": self.port, "addresses": len(self.addresses)},
            )
        except Exception as exc:  # noqa: BLE001 -- discovery is best-effort
            log.warning("mdns_advertise_failed", extra={"error": repr(exc)})
            await self.stop()

    async def stop(self) -> None:
        if self._zc is not None and self._info is not None:
            try:
                await self._zc.async_unregister_service(self._info)
            except Exception:  # noqa: BLE001
                log.debug("mdns_unregister_failed")
        if self._zc is not None:
            try:
                await self._zc.async_close()
            except Exception:  # noqa: BLE001
                log.debug("mdns_close_failed")
        self._zc = None
        self._info = None

    def txt(self) -> dict[str, Any]:
        return dict(self.properties)
