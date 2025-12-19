# Webmin WireGuard Module

This Webmin module provides a native Perl/CGI interface to manage existing WireGuard deployments on Debian hosts or Docker-based setups. The module **never installs or upgrades WireGuard**; it only reads and updates configuration files and performs safe runtime actions through `wg`, `wg-quick`, or Docker.

## Features
- Automatic backend detection:
  - Host mode when `/usr/bin/wg`, `/etc/wireguard`, and `wg-quick@` units are available.
  - Docker mode when Docker is reachable and a WireGuard-labelled container or configured container name is present.
- Clear UI banner showing the active backend (host or docker + container name).
- Interface overview with status, peer counts, and start/stop/restart/apply controls (honors Webmin ACL write restrictions).
- Peer management per interface:
  - Lists peers with optional `# Name:` comments, AllowedIPs, endpoints, and live handshake/RX/TX (when `wg show` is available).
  - Add peer form with IP auto-suggestion from a configurable pool, optional preshared/keepalive, and client config generation.
  - Optional QR rendering when `qrencode` is present.
  - Delete peer with confirmation and safe config backups.
- Configuration safety:
  - Timestamped backups with retention limits before edits.
  - Preserves file ownership/mode (0600) and validates interface names, keys, and AllowedIPs.
  - Supports Docker config directories or in-container actions, restarting the container to apply changes when `wg syncconf` is unavailable.

## Module configuration
The module reads `/etc/webmin/wireguard/config`. Key options:
- `config_dir` – Host WireGuard config directory (default `/etc/wireguard`).
- `docker_container_name` – Preferred WireGuard container name/ID (optional).
- `docker_config_dir` – Host path where container WireGuard configs are mounted.
- `docker_iface_list_strategy` – `host_dir` (default) or `docker_exec` to enumerate configs from inside the container.
- `client_pool_cidr` – CIDR used to auto-suggest next peer IP (default `10.0.0.0/24`).
- `backup_retention` – Number of backups to keep (default 10).
- `enable_qr` – Toggle QR generation when `qrencode` is installed.
- `default_endpoint`, `default_dns`, `default_client_allowed_ips` – Defaults for client configs.

## SECURITY NOTES
- Restrict Webmin access to trusted networks/VPN only; prefer running Webmin behind a WireGuard tunnel itself.
- Apply host-level firewall rules (e.g., UFW) to allow SSH on trusted addresses and limit Webmin’s listening interface/ports.
- Ensure Webmin ACLs limit WireGuard editing to trusted administrators; the module disables write actions when ACLs are read-only.

## INSTALL.md
1. Copy the module into Webmin’s modules directory:
   ```bash
   sudo cp -r /path/to/webmin-wireguard-module /usr/share/webmin/wireguard
   sudo cp /usr/share/webmin/wireguard/config /etc/webmin/wireguard/config
   ```
2. Clear module cache and restart Webmin:
   ```bash
   sudo /etc/webmin/restart
   ```
3. Open Webmin → Refresh Modules, then navigate to **Networking → WireGuard**.
