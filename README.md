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

### Local REALITY websites

Set `REALITY_TARGETS_FILE` to a readable, non-empty YAML mapping from the panel's
REALITY SNI names to local HTTPS destinations:

```yaml
site.example.com: "127.0.0.1:48080"
second.example.com: "127.0.0.1:48080"
```

Both kernels apply the mapping only to matching VLESS/Trojan REALITY nodes.
The panel's SNI, credentials and listener ports stay unchanged. Unmatched nodes
retain their existing destination behavior. Only loopback IP destinations are
accepted; an explicitly configured missing, empty or invalid file stops
configuration loading. The file must be readable inside the container. Restart
the node after changing the mapping; changing this file alone does not trigger
hot reload.

In XBoard, put the website domain in **伪装站点（dest）** (`server_name`). Put the
loopback HTTPS address and port in the mapping file. A matching entry replaces
the entire handshake destination, including its port; the panel's
`reality_settings.server_port` is not used for that entry. Keep the VLESS
connection and server listener ports as configured for that node. Set the
client's SNI to the same website domain and refresh its subscription.
A website listening only on loopback requires `REALITY_TARGETS_FILE`.

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
