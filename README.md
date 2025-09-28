# argosec_lite

**argosec_lite** is an automated security deployment and hardening tool for Linux servers. It installs and configures Suricata as an IPS, sets up system and kernel-level protections for common exploits and DDoS attacks, deploys iptables rules, enables UFW firewall (allowing only SSH, Shadowsocks, and DNS), installs and configures Shadowsocks as an Outline-compatible proxy server, sets up portsentry as an anti-portscan tool, and deploys Pi-hole as a DNS server. I suggest also add manual installation of pihole for a dns firewall.

---

## Features

- **Suricata IPS** with custom rules against DDoS, malformed packets, port scanning, DNS amplification, and NTP DDoS attacks.
- **Sysctl hardening** for kernel and network parameters.
- **Persistent iptables rules** for attack mitigation.
- **UFW firewall:** Only SSH, Shadowsocks (port 8388), and DNS (port 53) allowed in; logging enabled for all traffic.
- **Shadowsocks-libev proxy:** Outline-compatible, safe access key generated and printed for use in Outline client (mobile/desktop).
- **ntpsec:** Secure and up-to-date NTP server.
- **Portsentry:** Protection against port scanning attacks.
- **Pi-hole DNS server:** Blocks ads and trackers network-wide; ready for local DNS.
- **Automated service deployment:** All services are enabled and started automatically on boot.

---

## IMPORTANT

- All tools come with **basic features** enabled and default rules.
- **You must add your own blacklist for Pi-hole** to block additional domains (ads, malware, trackers etc).  
  - Add blocklists via Pi-hole's web interface or `gravity` script.
- **You must enable Suricata sources** for updated community, emerging, and threat rules:
  - Edit `/etc/suricata/suricata.yaml` and add/update source URLs.
  - Run `suricata-update` for the latest rules.
- Review all configurations for your environment before putting the system into production.
- In some debian distro issue installing Flask, i strongly suggest to install python3-flask before deploy argosec.

---

## Requirements

- Ubuntu/Debian 20.04+ (other distros may require small changes)
- Python 3.8+
- Root privileges

## Installation

1. **Clone the repository or download the script:**

    ```bash
    git clone https://github.com/psychomad/argosec_lite.git
    cd argosec_lite
    ```

    Or just download the `deploy_argosec.py` file.

2. **Run the deployment script:**

    ```bash
    sudo python3 deploy_argosec.py
    ```

    > **Note:** You must run as `root` (or with `sudo`).

3. **Follow on-screen instructions.**  
   The script will:
   - Install all required packages (`suricata`, `ntpsec`, `iptables-persistent`, `shadowsocks-libev`, `ufw`, `portsentry`, `Pi-hole`).
   - Detect your public network interface.
   - Deploy Suricata IPS and custom rules.
   - Harden system kernel parameters via `/etc/sysctl.conf`.
   - Apply persistent iptables rules.
   - Enable and configure ntpsec.
   - Set up UFW firewall (SSH, Shadowsocks, Pi-hole DNS allowed in).
   - Deploy Shadowsocks proxy and print your Outline access key for mobile/desktop.
   - Install and enable portsentry.
   - Install Pi-hole for local DNS filtering.

4. **Connect to Shadowsocks using Outline client:**

    - Copy the access key printed by the script (starts with `ss://`).
    - Open the Outline app, click "+" and paste the access key.

5. **Manage your Pi-hole DNS server:**
    - Access Pi-hole's web UI at [http://your-server-ip/admin](http://your-server-ip/admin)
    - Add blocklists, enable advanced filtering, and monitor DNS queries.

6. **Update Suricata rules:**
    - Add new sources in `/etc/suricata/suricata.yaml`
    - Run `suricata-update` to fetch the latest community and threat rules.

---

## Example Output

```text
Shadowsocks server deployed for Outline client.
Connect using this access key (Outline compatible):
ss://Y2hhY2hhMjAtaWV0Zi1wb2x5MTM1OnNvbWVsb25ncGFzc3dvcmQ@192.168.1.100:8388/?outline=1
```
You can use with public IP or internal LAN
---

## Uninstall

To remove all installed packages (except sysctl modifications):

```bash
sudo apt-get remove --purge suricata ntpsec iptables-persistent shadowsocks-libev ufw portsentry
```

## Notes

- Sysctl changes are made in `/etc/sysctl.conf` (review before/after running).
- UFW rules are reset and only SSH, Shadowsocks, DNS are allowed in.
- Shadowsocks config is written to `/etc/shadowsocks-libev/config.json`.
- Pi-hole admin panel is available at `http://<server_ip>/admin`.
- All commands are logged to stdout.

## License

MIT

## Author

Argo from CenturiaLabs
