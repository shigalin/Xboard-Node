# xboard-node

Node backend for [Xboard](https://github.com/cedar2025/Xboard). Supports `sing-box` / `xray-core` dual kernels.

> **Disclaimer**: This project is for educational and learning purposes only.

## Features

- Protocols: V2Ray family, Trojan, Shadowsocks, Hysteria2, TUIC, AnyTLS
- Sync: WebSocket push + REST polling dual channel
- User controls: speed limit, device limit, alive-IP tracking, hot update
- Deploy modes: node mode, machine mode, standalone mode
- Multi-instance: single process binding multiple panels / nodes

## Install

### Docker

```bash
docker run -d --restart=always --network=host --stop-timeout=120 \
  -e apiHost=https://panel.com -e apiKey=TOKEN -e nodeID=1 \
  ghcr.io/shigalin/xboard-node:latest
```

Allow at least 120 seconds for graceful shutdown (for example, set Compose
`stop_grace_period: 120s`); the node waits for pending traffic reports and
final connection counters before exiting. Existing containers also need their
stop timeout updated when they are recreated.

### Docker Compose

```bash
git clone -b compose --depth 1 https://github.com/shigalin/xboard-node.git
cd xboard-node
vim config/config.yml   # set panel.url / token / node_id
docker compose up -d
```

### Installer (Linux systemd)

```bash
# Node mode
curl -fsSL https://raw.githubusercontent.com/shigalin/xboard-node/dev/install.sh | \
  sudo bash -s -- --mode node --panel https://panel.example.com --token TOKEN --node-id 1

# Machine mode
curl -fsSL https://raw.githubusercontent.com/shigalin/xboard-node/dev/install.sh | \
  sudo bash -s -- --mode machine --panel https://panel.example.com --token TOKEN --machine-id 1
```

## xbctl

Run `xbctl` after installation for help. Common commands:

```bash
xbctl list                          # list all instances
xbctl status                        # running status
xbctl bind add-node --panel URL --token TOKEN --node-id 1
xbctl bind add-machine --panel URL --token TOKEN --machine-id 1
xbctl bind remove-node --panel URL --node-id 1
xbctl service restart
```

## Configuration

Legacy single-panel config is fully compatible. Appending bindings auto-migrates to `instances` format. See `config.yml.example`.

**Multi-node certificate upgrade:** If a static multi-node installation has
`cert.pem` or `key.pem` in its old shared default `cert_dir`, the new binary
refuses to start until each affected node has a distinct `nodes[].cert.cert_dir`.
Before upgrading, back up the existing certificate and key, identify which
node/domain they actually cover, then place a matching pair in that node's
private directory (or reissue it) and configure unique directories for all
nodes. `nodes[].cert` replaces the entire inherited certificate configuration,
so include any other required certificate settings alongside `cert_dir`.
Do not assign a certificate to a node whose domain it does not cover;
do not remove the original files until each node's TLS handshake has been
verified. Even a locally configured `cert_mode: none` cannot bypass this check:
the panel may still supply content-mode TLS that relies on the persisted pair.
No certificate is moved automatically.

For a release, verify the candidate against an isolated Linux node and the
**actual** panel (including user revocation, reconnect and shutdown traffic
reports) before replacing a live node. Give Docker at least 120 seconds to
stop; existing containers must be recreated with the stop timeout or Compose
grace period. Passing local tests or a synthetic-panel smoke test alone is
not production acceptance.

For panel-backed nodes, Hysteria (v1 and v2) always runs on `singbox` and XHTTP/SplitHTTP
always runs on `xray`, regardless of `kernel.type`. A switch restarts the
listener. Use a `kernel.custom_config` file written for the selected kernel.
When applying a config or starting a kernel, the node rejects recognized
foreign options such as `route`, `routing`, and kernel-specific DNS fields.
Edits to the file take effect on the next config apply or kernel start.

In machine mode, use `nodes[].node_id` and `nodes[].kernel.custom_config`
to supply a separate native file for a discovered node. Entries override the
matching node's settings. The panel still controls which nodes are discovered.

Hysteria v1 uses the `hysteria` ALPN by default. Update clients that explicitly
set `h3`. Credential changes on a Hysteria v1 node rebuild its inbound and
disconnect its current QUIC sessions. For panel-managed Hysteria nodes, the
panel's download limit becomes the server's upload limit, and vice versa.
Standalone bandwidth values are already server-side. Hysteria2 uses Brutal
for server sends when the client advertises a nonzero receive rate. The
server's upload limit caps that rate. A client advertising zero still uses
the server's BBR path.

### REALITY destinations selected by panel SNI list (Xray)

In the panel's existing REALITY **伪装站点(dest)** / SNI field, enter DNS names
separated by ASCII commas, for example `site.example.com,www.apple.com`. Set the
single REALITY **端口(port)** to `443` (or the shared target port). No additional
node-side SNI list is needed.

The node API keeps the complete comma-separated string. xboard-node trims and
normalizes the names, removes duplicates, and accepts each listed SNI. For each
connection it forwards the original TLS handshake to `<client SNI>:<shared port>`.
The client keeps its node address, connection port, UUID and REALITY credentials;
only `servername` / `serverName` changes. Updated Xboard subscriptions use the
first name as their default SNI. Upgrade both Xboard and xboard-node before using
multiple names. Each target must accept its SNI and support REALITY's handshake.

The node uses a local Unix socket for internal forwarding: on Linux an abstract
socket, which has no file for `/tmp` cleaners to delete; elsewhere a socket in a
private temporary directory. It does not need Nginx or an Xray-core patch, and
does not terminate TLS. Fragmented ClientHello
records are reassembled only to read SNI, then all original bytes are replayed
unchanged. Connections without a listed SNI (unknown or absent SNI, non-TLS or
malformed input, or a ClientHello not complete within 15 seconds or 256 KiB)
are replayed unchanged to the first listed name's destination, so probes see
that site instead of a closed connection. Destinations are never constructed
from unlisted client input. Unchanged mappings, including the first name, share
their router across overlapping reload generations, retaining REALITY
probe-cache keys. The router closes all forwarding connections
when its last owning generation closes.

The existing `reality_targets_file` can still override individual listed domains
with local HTTPS addresses, including their ports. Without such an override,
every domain uses the one panel REALITY port (default `443`). A local site must
have its own HTTPS listener; do not target the node's public REALITY listener.
Malformed lists and invalid shared ports reject the new configuration without
replacing a running instance. Single-name behavior is unchanged. This feature
is for Xray; sing-box nodes reject a comma-separated SNI as invalid node
configuration.

### Local REALITY websites

Point `kernel.reality_targets_file` (or the `realityTargetsFile` /
`REALITY_TARGETS_FILE` env vars, which take precedence) at a readable, non-empty
YAML mapping from the panel's REALITY SNI names to local HTTPS destinations:

```yaml
site.example.com: "127.0.0.1:48080"
second.example.com: "127.0.0.1:48080"
ipv6.example.com: "[::1]:48080"    # bracketed IPv6 must be quoted in YAML
```

Both kernels apply the mapping only to REALITY nodes (`tls: 2`) whose SNI
matches. The panel's SNI, credentials and listener ports stay unchanged;
unmatched nodes retain their existing destination behavior. In multi-instance
mode each instance may set its own file, and an instance without one inherits
the top-level setting — so an instance cannot opt out by leaving the field
empty. The env vars are process-wide and replace every instance's own file.

Only loopback IP destinations are accepted, so the website must listen in the
same network namespace as the node process — a site in a separate container,
reachable only on a bridge address or service name, cannot be used. An
explicitly configured missing, empty or invalid file stops configuration
loading, so a node never silently falls back to dialing its own public
listener; when a mapping is loaded but a node's SNI is absent from it, the node
logs a warning and keeps the panel destination. Restart the node after changing
the mapping; changing this file alone does not trigger hot reload.

In XBoard, put the website domain in **伪装站点（dest）** (`server_name`). Put the
loopback HTTPS address and port in the mapping file. A matching entry replaces
the entire handshake destination, including its port; the panel's
`reality_settings.server_port` is not used for that entry. Keep the VLESS
connection and server listener ports as configured for that node. Set the
client's SNI to the same website domain and refresh its subscription.
A website listening only on loopback requires this mapping.

`xboard-node --supports-reality-targets` prints `reality-targets-v1` when supported.
`xboard-node --check-reality-targets /path/to/targets.yml` validates the mapping
without starting listeners or contacting the panel. Existing published images
need to be rebuilt with this feature before deployment scripts can use it.

## Extensions

- Custom routes: [docs-custom-routes.md](docs-custom-routes.md)
- Custom outbounds: [docs-custom-outbounds.md](docs-custom-outbounds.md)
- DNS providers (ACME DNS-01): [docs-dns-providers.md](docs-dns-providers.md)

## License

MPL-2.0.
