# Installation

1. Copy the module into Webmin’s module directory (adjust source path as needed):
   ```bash
   sudo cp -r /path/to/webmin-wireguard-module /usr/share/webmin/wireguard
   sudo cp /usr/share/webmin/wireguard/config /etc/webmin/wireguard/config
   ```
2. Clear the module cache and restart Webmin:
   ```bash
   sudo /etc/webmin/restart
   ```
3. In Webmin, click **Refresh Modules**, then open **Networking → WireGuard**.

## SECURITY NOTES
- Limit Webmin exposure to VPN or allowlisted IPs; avoid exposing the login over the internet.
- Keep SSH locked down (e.g., UFW with allowlist) and prefer key-based auth.
