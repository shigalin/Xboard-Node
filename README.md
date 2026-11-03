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
docker run -d --restart=always --network=host \
  -e apiHost=https://panel.com -e apiKey=TOKEN -e nodeID=1 \
  ghcr.io/shigalin/xboard-node:latest
```

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

### REALITY destinations selected by client SNI (Xray)

Set `kernel.reality_sni_targets` to let clients of the **same Xray REALITY node**
choose among explicitly configured camouflage websites by changing their SNI:

```yaml
kernel:
  type: xray
  reality_sni_targets:
    site.example.com: "127.0.0.1:48080"
    www.apple.com: "www.apple.com:443"
```

The map must include the panel's REALITY `server_name`, so the existing
subscription keeps working. The client keeps its node address, port, UUID and
REALITY credentials; only its `servername` / `serverName` changes. Each target
must accept its mapped SNI and support REALITY's TLS handshake requirements.
Use lowercase DNS names (IDNs in ASCII/Punycode) and an explicit destination
port; IPv6 destinations use `[address]:port`. Names are normalized at load.
Wildcards, IP-valued SNI names and malformed destinations are rejected.

The node starts an internal Xray router on a private Unix socket and forwards
the original TLS handshake according to SNI. No Nginx, extra public listener,
or Xray-core patch is needed. Unknown/absent SNI and non-TLS traffic are blocked;
destinations are never constructed from arbitrary client input. Ordinary TLS
probes for a listed SNI reach that SNI's website too. These handshake connections
do not use the proxy users' custom routes or affect their device/IP counts.
Explicit loopback targets are supported without relaxing the proxy's ordinary
private-address restrictions. Do not point a target back to the node's own
REALITY listener; a local site must have its own HTTPS listener in the same
network namespace.

This map applies only to Xray REALITY inbounds and takes precedence over the
static destination, including `reality_targets_file`. A non-empty per-instance
map replaces the inherited top-level map; an omitted/empty map inherits it.
Restart the node after editing the YAML. Without this map, existing behavior
is unchanged. sing-box is unaffected. Invalid maps fail configuration loading;
a panel update whose default SNI is missing from the map fails without replacing
the running Xray instance. Routers are closed with their owning instances,
including draining generations after reload.

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
