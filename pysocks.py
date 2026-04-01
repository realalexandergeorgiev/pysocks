#!/usr/bin/env python3
"""
Minimal async SOCKS5 server — stdlib only, listens on 0.0.0.0:1080

Supports:
  - CONNECT       (TCP proxy, RFC 1928 §6)
  - UDP ASSOCIATE (RFC 1928 §7) — designed for tun2socks

UDP ASSOCIATE notes:
  - One UDP relay socket is bound per ASSOCIATE request (ephemeral port)
  - Relay lifetime is tied to the TCP control connection (RFC requirement)
  - FRAG != 0 datagrams are dropped (fragmentation not supported)
  - tun2socks sends client hint 0.0.0.0:0 — real client addr is learned
    from the first incoming UDP datagram
  - DNS resolution inside the relay is blocking (stdlib limitation);
    fine for lab use, not production
"""

import asyncio
import logging
import socket
import struct
from typing import Optional

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
log = logging.getLogger(__name__)

HOST = "0.0.0.0"
PORT = 1080

# ---------------------------------------------------------------------------
# SOCKS5 constants (RFC 1928)
# ---------------------------------------------------------------------------
VER            = 0x05
AUTH_NONE      = 0x00
AUTH_NO_MATCH  = 0xFF

CMD_CONNECT    = 0x01
CMD_UDP_ASSOC  = 0x03

ATYP_IPV4      = 0x01
ATYP_DOMAIN    = 0x03
ATYP_IPV6      = 0x04

REP_SUCCESS    = 0x00
REP_FAILURE    = 0x01
REP_REFUSED    = 0x05
REP_CMD_UNSUP  = 0x07
REP_ATYP_UNSUP = 0x08


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

async def read_exact(reader: asyncio.StreamReader, n: int) -> bytes:
    return await reader.readexactly(n)


def encode_addr_port(addr: str, port: int) -> bytes:
    """Encode address+port as SOCKS5 ATYP+ADDR+PORT bytes."""
    try:
        packed = socket.inet_aton(addr)
        return struct.pack("!B4sH", ATYP_IPV4, packed, port)
    except OSError:
        pass
    try:
        packed = socket.inet_pton(socket.AF_INET6, addr)
        return struct.pack("!B16sH", ATYP_IPV6, packed, port)
    except OSError:
        pass
    enc = addr.encode()
    return struct.pack(f"!BB{len(enc)}sH", ATYP_DOMAIN, len(enc), enc, port)


async def send_reply(writer: asyncio.StreamWriter, rep: int,
                     bind_addr: str = "0.0.0.0", bind_port: int = 0) -> None:
    reply = bytes([VER, rep, 0x00]) + encode_addr_port(bind_addr, bind_port)
    writer.write(reply)
    await writer.drain()


async def pipe(reader: asyncio.StreamReader,
               writer: asyncio.StreamWriter) -> None:
    """One-directional byte relay."""
    try:
        while True:
            data = await reader.read(65536)
            if not data:
                break
            writer.write(data)
            await writer.drain()
    except (asyncio.IncompleteReadError, ConnectionResetError,
            BrokenPipeError, OSError):
        pass
    finally:
        try:
            writer.close()
        except Exception:
            pass


# ---------------------------------------------------------------------------
# UDP datagram framing (RFC 1928 §7)
# ---------------------------------------------------------------------------
#
#  SOCKS5 UDP request/response header:
#  +-----+------+------+----------+----------+----------+
#  | RSV | FRAG | ATYP | DST.ADDR | DST.PORT |   DATA   |
#  +-----+------+------+----------+----------+----------+
#  |  2  |  1   |  1   | variable |    2     | variable |
#  +-----+------+------+----------+----------+----------+

def parse_udp_header(data: bytes) -> Optional[tuple]:
    """
    Parse SOCKS5 UDP header.
    Returns (frag, dst_host, dst_port, payload) or None on error.
    """
    if len(data) < 4:
        return None
    # RSV (2 bytes) must be 0x0000 per RFC 1928
    if data[0:2] != b"\x00\x00":
        return None
    frag = data[2]
    atyp = data[3]
    offset = 4

    if atyp == ATYP_IPV4:
        if len(data) < offset + 6:
            return None
        dst_host = socket.inet_ntoa(data[offset:offset + 4])
        offset += 4
    elif atyp == ATYP_IPV6:
        if len(data) < offset + 18:
            return None
        dst_host = socket.inet_ntop(socket.AF_INET6, data[offset:offset + 16])
        offset += 16
    elif atyp == ATYP_DOMAIN:
        if len(data) < offset + 1:
            return None
        dlen = data[offset]; offset += 1
        if len(data) < offset + dlen + 2:
            return None
        dst_host = data[offset:offset + dlen].decode(errors="replace")
        offset += dlen
    else:
        return None

    if len(data) < offset + 2:
        return None
    dst_port = struct.unpack("!H", data[offset:offset + 2])[0]
    return frag, dst_host, dst_port, data[offset + 2:]


def build_udp_header(src_host: str, src_port: int) -> bytes:
    """Build the SOCKS5 UDP response header (RSV=0, FRAG=0)."""
    # RSV(2) + FRAG(1) prefix, then ATYP+ADDR+PORT
    return b"\x00\x00\x00" + encode_addr_port(src_host, src_port)


# ---------------------------------------------------------------------------
# UDP relay — one instance per UDP ASSOCIATE session
# ---------------------------------------------------------------------------

class UDPRelay(asyncio.DatagramProtocol):
    """
    Bidirectional UDP relay between SOCKS5 client and arbitrary targets.

    Client → relay:
        Receives SOCKS5-framed datagrams, strips header, forwards raw payload
        to the real destination.

    Target → relay:
        Receives raw reply, wraps in SOCKS5 header, forwards to client_addr.

    The client's real address is unknown at ASSOCIATE time (tun2socks sends
    0.0.0.0:0 as the hint). We learn it from the first datagram we receive.
    """

    def __init__(self, loop: asyncio.AbstractEventLoop) -> None:
        self.loop = loop
        self.transport: Optional[asyncio.DatagramTransport] = None
        self.client_addr: Optional[tuple] = None

    # ---- asyncio protocol interface ----------------------------------------

    def connection_made(self, transport: asyncio.DatagramTransport) -> None:
        self.transport = transport
        host, port = transport.get_extra_info("sockname")
        log.info("UDP relay bound on %s:%s", host, port)

    def datagram_received(self, data: bytes, addr: tuple) -> None:
        # Debug: log raw incoming datagram and source address
        try:
            log.debug("UDP relay recv from %r (%d B): %s", addr, len(data), data.hex())
        except Exception:
            log.debug("UDP relay recv from %r (%d B)", addr, len(data))

        if self.client_addr is None:
            # First packet — learn client address
            self.client_addr = addr
            log.info("UDP relay: client addr learned as %s:%s", *addr)

        if addr == self.client_addr:
            asyncio.ensure_future(self._from_client(data))
        else:
            self._from_target(data, addr)

    def error_received(self, exc: Exception) -> None:
        log.warning("UDP relay socket error: %s", exc)

    def connection_lost(self, exc: Exception) -> None:
        log.info("UDP relay socket closed")

    # ---- relay paths --------------------------------------------------------

    async def _from_client(self, data: bytes) -> None:
        parsed = parse_udp_header(data)
        if parsed is None:
            # Log raw payload for debugging header parsing issues
            log.warning("UDP relay: malformed header from client, dropping; raw=%s", data.hex())
            return
        frag, dst_host, dst_port, payload = parsed
        if frag != 0:
            # Fragmentation reassembly not implemented — drop silently
            log.debug("UDP relay: dropping fragmented datagram (frag=%d)", frag)
            return
        try:
            # Offload OS resolver to a thread-pool worker so the event loop
            # stays unblocked while DNS is in flight.
            # Ensure we resolve addresses suitable for the relay socket
            # family (e.g., avoid returning IPv6 when relay is IPv4-only).
            sock_family = socket.AF_UNSPEC
            if self.transport is not None:
                sock = self.transport.get_extra_info("socket")
                if sock is not None and hasattr(sock, "family"):
                    sock_family = sock.family

            infos = await self.loop.run_in_executor(
                None,
                socket.getaddrinfo,
                dst_host,
                dst_port,
                sock_family,
                socket.SOCK_DGRAM,
            )
            if not infos:
                return
            dst_addr = infos[0][4]
            self.transport.sendto(payload, dst_addr)
            log.debug("UDP → %s:%s  %d B", dst_host, dst_port, len(payload))
        except OSError as exc:
            log.warning("UDP relay: send to %s:%s failed: %s",
                        dst_host, dst_port, exc)

    def _from_target(self, data: bytes, addr: tuple) -> None:
        if self.client_addr is None:
            return
        # Debug: log target reply details
        try:
            log.debug("UDP reply from target %r (%d B): %s", addr, len(data), data.hex())
        except Exception:
            log.debug("UDP reply from target %r (%d B)", addr, len(data))

        src_host, src_port = addr[0], addr[1]
        wrapped = build_udp_header(src_host, src_port) + data
        self.transport.sendto(wrapped, self.client_addr)
        log.debug("UDP ← %s:%s  %d B", src_host, src_port, len(data))

    # ---- lifecycle ----------------------------------------------------------

    @property
    def bind_addr(self) -> tuple:
        if self.transport:
            return self.transport.get_extra_info("sockname")
        return ("0.0.0.0", 0)

    def close(self) -> None:
        if self.transport and not self.transport.is_closing():
            self.transport.close()


# ---------------------------------------------------------------------------
# TCP connection dispatcher
# ---------------------------------------------------------------------------

async def handle(reader: asyncio.StreamReader,
                 writer: asyncio.StreamWriter) -> None:
    peer = writer.get_extra_info("peername")
    log.info("Connection from %s:%s", *peer)
    try:
        await _socks5_session(reader, writer)
    except asyncio.IncompleteReadError:
        pass
    except Exception as exc:
        log.warning("Session %s:%s ended: %s", *peer, exc)
    finally:
        if not writer.is_closing():
            writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass


async def _socks5_session(reader: asyncio.StreamReader,
                           writer: asyncio.StreamWriter) -> None:
    # ---- Auth negotiation --------------------------------------------------
    ver, nmethods = await read_exact(reader, 2)
    if ver != VER:
        raise ValueError(f"Not SOCKS5 (ver={ver:#x})")

    methods = await read_exact(reader, nmethods)
    if AUTH_NONE not in methods:
        writer.write(bytes([VER, AUTH_NO_MATCH]))
        await writer.drain()
        raise ValueError("No acceptable auth method offered")

    writer.write(bytes([VER, AUTH_NONE]))
    await writer.drain()

    # ---- Request -----------------------------------------------------------
    ver, cmd, _, atyp = await read_exact(reader, 4)
    if ver != VER:
        raise ValueError(f"Bad request ver={ver:#x}")

    # Destination address
    if atyp == ATYP_IPV4:
        dst_host = socket.inet_ntoa(await read_exact(reader, 4))
    elif atyp == ATYP_IPV6:
        dst_host = socket.inet_ntop(socket.AF_INET6, await read_exact(reader, 16))
    elif atyp == ATYP_DOMAIN:
        dlen = (await read_exact(reader, 1))[0]
        dst_host = (await read_exact(reader, dlen)).decode()
    else:
        await send_reply(writer, REP_ATYP_UNSUP)
        raise ValueError(f"Unsupported ATYP {atyp:#x}")

    dst_port = struct.unpack("!H", await read_exact(reader, 2))[0]

    if cmd == CMD_CONNECT:
        await _cmd_connect(reader, writer, dst_host, dst_port)
    elif cmd == CMD_UDP_ASSOC:
        await _cmd_udp_associate(reader, writer, dst_host, dst_port)
    else:
        await send_reply(writer, REP_CMD_UNSUP)
        raise ValueError(f"Unsupported CMD {cmd:#x}")


# ---------------------------------------------------------------------------
# CONNECT
# ---------------------------------------------------------------------------

async def _cmd_connect(reader: asyncio.StreamReader,
                        writer: asyncio.StreamWriter,
                        dst_host: str, dst_port: int) -> None:
    log.info("CONNECT → %s:%s", dst_host, dst_port)
    try:
        t_reader, t_writer = await asyncio.wait_for(
            asyncio.open_connection(dst_host, dst_port), timeout=10
        )
    except ConnectionRefusedError:
        await send_reply(writer, REP_REFUSED)
        raise
    except (OSError, asyncio.TimeoutError):
        await send_reply(writer, REP_FAILURE)
        raise

    bind = t_writer.get_extra_info("sockname")
    await send_reply(writer, REP_SUCCESS,
                     bind_addr=bind[0] if bind else "0.0.0.0",
                     bind_port=bind[1] if bind else 0)

    log.info("TCP tunnel up → %s:%s", dst_host, dst_port)
    await asyncio.gather(
        pipe(reader, t_writer),
        pipe(t_reader, writer),
        return_exceptions=True,
    )
    log.info("TCP tunnel down ← %s:%s", dst_host, dst_port)


# ---------------------------------------------------------------------------
# UDP ASSOCIATE
# ---------------------------------------------------------------------------

async def _cmd_udp_associate(reader: asyncio.StreamReader,
                              writer: asyncio.StreamWriter,
                              hint_host: str, hint_port: int) -> None:
    """
    RFC 1928 §7 — UDP ASSOCIATE

    Bind a UDP relay socket, reply with its address, then hold the TCP
    control connection open. When the TCP connection closes (client or
    server side), tear down the UDP relay immediately.
    """
    log.info("UDP ASSOCIATE (client hint %s:%s)", hint_host, hint_port)

    loop = asyncio.get_running_loop()
    relay = UDPRelay(loop)

    # Bind on the same IP the TCP server accepted on
    server_ip = writer.get_extra_info("sockname")[0]
    sock_family = socket.AF_INET6 if ":" in server_ip else socket.AF_INET
    transport, _ = await loop.create_datagram_endpoint(
        lambda: relay,
        local_addr=(server_ip, 0),   # port 0 → OS picks ephemeral port
        family=sock_family,
        allow_broadcast=True,
    )

    bind_host, bind_port = relay.bind_addr
    await send_reply(writer, REP_SUCCESS,
                     bind_addr=bind_host, bind_port=bind_port)

    # Keep TCP control connection alive; close relay when it drops
    try:
        await _drain_until_close(reader)
    finally:
        relay.close()
        log.info("UDP ASSOCIATE ended (was bound %s:%s)", bind_host, bind_port)


async def _drain_until_close(reader: asyncio.StreamReader) -> None:
    """
    Consume (and discard) any data on reader until EOF or error.
    Purpose: detect TCP control connection teardown per RFC 1928.
    """
    try:
        while True:
            # SOCKS5 TCP control connection must remain alive indefinitely 
            # while the UDP relay is active. Block until EOF or error.
            data = await reader.read(256)
            if not data:
                break
    except (ConnectionResetError, BrokenPipeError, OSError):
        pass


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

async def main() -> None:
    server = await asyncio.start_server(handle, HOST, PORT)
    addrs = ", ".join(str(s.getsockname()) for s in server.sockets)
    log.info("SOCKS5 listening on %s  [CONNECT + UDP ASSOCIATE]", addrs)
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        log.info("Shutting down.")
