# sni-spoof

Go port of [@patterniha](https://github.com/patterniha)'s SNI-Spoofing / DPI-bypass TCP forwarder — **his idea, all credit to him**. This is just a faithful reimplementation of the original Windows (WinDivert + Python) tool.

**Linux and macOS.** Linux uses `AF_PACKET` raw sockets (`CAP_NET_RAW` / root). macOS uses BPF via `/dev/bpf*` (needs root, or r/w access to a bpf device).

## How it works

A local TCP forwarder that tricks stateful DPI into whitelisting the flow before the real TLS ClientHello is sent:

1. Accept a client, dial the upstream, let the kernel do the TCP 3-way handshake normally.
2. An `AF_PACKET` sniffer watches the handshake. It records the outbound SYN's ISN, and the instant it sees the outbound 3rd-handshake ACK it injects a crafted TLS ClientHello frame carrying an innocuous `FAKE_SNI` (e.g. `security.vercel.com`).
3. The fake packet uses `seq = ISN + 1 - len(fake)` — i.e. a sequence number *before* the server's receive window. **DPI parses it and whitelists the connection; the server drops it as out-of-window.**
4. The sniffer waits for the server's reply ACK with `ack == ISN + 1`, which proves the server ignored the fake and is still expecting the real byte stream. Only then does the forwarder start relaying real client↔server data. The real ClientHello is now invisible to DPI.
5. If that confirmation doesn't arrive within 2s, the connection is aborted.

## Release

Releases are published with `scripts/release.sh`, not by CI: this repo is a
fork, and GitHub Actions stays disabled on forks, so tag pushes build nothing.

```
scripts/release.sh v0.6.0
```

It cross-compiles the four platforms, updates the installer's pinned SHA-256 to
match the artifact being published, tags, pushes, publishes the release, then
re-downloads every asset and verifies it against the pin.

Binaries are built with `-buildvcs=false` so the checksum is reproducible for a
given Go toolchain. Changing the Go version changes the output bytes, so
rebuild and re-pin with the same script rather than by hand.

## Build / run

```
go build -buildvcs=false -o sni-spoof .
sudo ./sni-spoof config.json
```

Works on Linux and macOS (amd64 / arm64). On macOS you may need to allow the binary to open `/dev/bpf*` — running under `sudo` is the simplest option.

`config.json`:
```json
{
  "LISTEN_HOST": "0.0.0.0",
  "LISTEN_PORT": 40443,
  "CONNECT_IP": "104.18.4.130",
  "CONNECT_PORT": 443,
  "FAKE_SNI": "security.vercel.com"
}
```

Point your client (xray, etc.) at `LISTEN_HOST:LISTEN_PORT` instead of the real upstream.
