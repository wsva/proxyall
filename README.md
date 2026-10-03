# Proxyall

A minimal transparent proxy for Windows, rewritten in Rust. It redirects **all**
outbound **TCP/IPv4** traffic through a single SOCKS5 or HTTP proxy, **except**
traffic from hardcoded processes, whose PIDs are resolved automatically at runtime
and kept up to date.

## How it works

`WinDivert` intercepts outbound IPv4/TCP packets in the kernel. For each new
connection the owning PID is looked up once (`GetExtendedTcpTable`) and a
DIRECT/PROXY decision is cached per source port, so later packets of the same
connection take a straight-line path (no lock, no table walk). Traffic is sent
**direct** when it is:

- loopback (`127.0.0.0/8`), broadcast/multicast, or
- from Proxyall itself, or
- from except processes

Everything else is rewritten to a local relay socket, which opens a
SOCKS5 `CONNECT` / HTTP `CONNECT` tunnel to the real destination through your
proxy and streams bytes both ways with `std::thread` + `io::copy`.

## Usage

Put `WinDivert.dll` and `WinDivert64.sys` next to `proxyall.exe`, then run
**as Administrator** (WinDivert installs a kernel driver):

## Build

```powershell
cargo build --release
```

## License

MIT
