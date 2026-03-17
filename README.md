# pysocks

A minimal, async SOCKS5 proxy server written in pure Python 3 — zero external dependencies, single file.

Built for use with [tun2socks](https://github.com/xjasonlyu/tun2socks) and similar TUN-based tunneling tools in lab and penetration testing environments.

## Features

- **CONNECT** — full TCP proxy with bidirectional relay
- **UDP ASSOCIATE** — RFC 1928 §7 compliant, designed for tun2socks
- IPv4, IPv6, and domain name targets
- No-auth only (unauthenticated SOCKS5)
- Async from top to bottom (`asyncio`, no threads)
- No dependencies outside the Python 3 stdlib

## Requirements

- Python 3.8+
- No `pip install` needed

## Usage

```bash
python3 pysocks.py
```

Listens on `0.0.0.0:1080` by default. Change `HOST` / `PORT` at the top of the file.

## tun2socks integration

This server is designed to be the SOCKS5 backend for tun2socks, which intercepts traffic at the TUN interface level and forwards it through the proxy — including UDP (DNS, etc.) without requiring proxychains.

### xjasonlyu/tun2socks (Go, recommended)

```bash
# Create and bring up the TUN interface
sudo ip tuntap add name tun0 mode tun
sudo ip link set tun0 up

# Start tun2socks pointed at this server
tun2socks -device tun0 -proxy socks5://127.0.0.1:1080

# Route traffic through tun0
sudo ip route add default dev tun0 metric 1
```

### hev-socks5-tunnel

```yaml
# tunnel.yaml
tunnel:
  name: tun0
  mtu: 8500
  ipv4: 198.18.0.1
socks5:
  address: 127.0.0.1
  port: 1080
  udp: udp
```

```bash
hev-socks5-tunnel tunnel.yaml
```

### Verify UDP is working

```bash
# DNS query over UDP through the relay
dig @8.8.8.8 google.com

# NTP sync over UDP
ntpdate -q time.google.com
```

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                        tun2socks                        │
│         (TUN interface → SOCKS5 client)                 │
└────────────────────┬────────────────────────────────────┘
                     │ TCP control connection
                     │ + UDP datagrams (SOCKS5-framed)
                     ▼
┌─────────────────────────────────────────────────────────┐
│                    pysocks.py                     │
│                                                         │
│  TCP listener :1080                                     │
│  ├── CONNECT  → asyncio stream relay                    │
│  └── UDP ASSOCIATE → UDPRelay (DatagramProtocol)        │
│       ├── client → strip SOCKS5 header → target         │
│       └── target → prepend SOCKS5 header → client       │
└────────────────────┬────────────────────────────────────┘
                     │ raw TCP / raw UDP
                     ▼
              real network targets
```

## UDP ASSOCIATE — implementation notes

| Behaviour | Detail |
|---|---|
| Client address | Learned from first incoming datagram; tun2socks sends `0.0.0.0:0` as hint |
| Relay lifetime | Tied to the TCP control connection — closed immediately on TCP EOF (RFC 1928 requirement) |
| Fragmentation | `FRAG != 0` datagrams are dropped; tun2socks does not use fragmentation |
| DNS resolution | Blocking `socket.getaddrinfo()` — fine for lab use, see Limitations |
| Bind address | Ephemeral port on the same interface as the TCP server |

## Limitations

- **No authentication** — do not expose port 1080 on untrusted networks.
- **No BIND command** — only CONNECT and UDP ASSOCIATE are implemented.
- **Blocking DNS in UDP relay** — `socket.getaddrinfo()` is synchronous. Under high concurrency with domain-name UDP targets this can stall the event loop. Fix: wrap in `loop.run_in_executor(None, socket.getaddrinfo, host, port)`.
- **IPv4 UDP relay only** — the UDP socket is bound as `AF_INET`. IPv6 UDP targets still work (resolved via `getaddrinfo`), but the relay socket itself is IPv4.
- **Raw packets (ICMP, SYN scans)** — not possible via SOCKS5. Use the real ligolo-ng binary if you need that.

## Configuration

Edit the constants at the top of `pysocks.py`:

```python
HOST = "0.0.0.0"   # listening interface
PORT = 1080         # listening port
```

Logging level can be changed by setting `level=` in `logging.basicConfig()`.

## Detection / OPSEC

- Presents as a plain, unauthenticated SOCKS5 server — no custom protocol fingerprint.
- No TLS. If you need encryption, put it behind an SSH tunnel or stunnel.
- tun2socks itself has a [known JARM fingerprint](https://necromancerlabs.com/research/papers/2025/gost-in-the-protocol/) when used with ligolo-ng — this server does not have that problem since it speaks standard SOCKS5.

## License

MIT
