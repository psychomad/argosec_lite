import subprocess
import os
import re
import sys
import socket
import secrets
import json
import shutil
import base64

def run(cmd, shell=False):
    print(f"Running: {cmd}")
    if "/usr/sbin" not in os.environ["PATH"]:
        os.environ["PATH"] += os.pathsep + "/usr/sbin"
    result = subprocess.run(cmd, shell=shell, capture_output=True, text=True)
    print(result.stdout)
    if result.returncode != 0:
        print(result.stderr)
    return result

def ensure_ufw_installed():
    ufw_path = shutil.which("ufw")
    if not ufw_path:
        print("UFW not found, installing ufw...")
        run(["apt-get", "update"])
        run(["apt-get", "install", "-y", "ufw"])
        ufw_path = shutil.which("ufw")
        if not ufw_path:
            print("Failed to install ufw. Exiting.")
            sys.exit(1)
    return ufw_path

def ensure_portsentry_installed():
    ps_path = shutil.which("portsentry")
    if not ps_path:
        print("Portsentry not found, installing portsentry...")
        run(["apt-get", "install", "-y", "portsentry"])
        ps_path = shutil.which("portsentry")
        if not ps_path:
            print("Failed to install portsentry. Exiting.")
            sys.exit(1)
    return ps_path

def get_public_interface():
    result = run(["ip", "route"], shell=False)
    for line in result.stdout.splitlines():
        if line.startswith("default "):
            parts = line.split()
            if "dev" in parts:
                idx = parts.index("dev")
                return parts[idx+1]
    return None

def get_server_ip(interface):
    result = run(["ip", "-4", "addr", "show", "dev", interface])
    for line in result.stdout.splitlines():
        line = line.strip()
        m = re.match(r"inet (\d+\.\d+\.\d+\.\d+)", line)
        if m:
            return m.group(1)
    try:
        return socket.gethostbyname(socket.gethostname())
    except Exception:
        return "127.0.0.1"

def install_packages():
    pkgs = [
        "suricata", "ntpsec", "iptables-persistent", "shadowsocks-libev", "ufw", "portsentry", "curl"
    ]
    run(["apt-get", "update"])
    run(["apt-get", "install", "-y"] + pkgs)

def deploy_suricata(interface):
    run(["systemctl", "enable", "suricata"])
    run(["systemctl", "stop", "suricata"])
    suricata_conf = "/etc/suricata/suricata.yaml"
    with open(suricata_conf, "r") as f:
        conf = f.read()
    conf = re.sub(r"interface: .*\n", f"interface: {interface}\n", conf)
    with open(suricata_conf, "w") as f:
        f.write(conf)
    rules = """
alert ip any any -> any any (msg:"Possible DDoS UDP flood"; threshold:type threshold, track by_src, count 100, seconds 1; sid:1000001; rev:1;)
alert tcp any any -> any any (msg:"Port Scan Detected"; flags:S; threshold:type threshold, track by_src, count 10, seconds 1; sid:1000002; rev:1;)
alert udp any any -> any 53 (msg:"DNS Amplification Attempt"; dsize:>100; sid:1000003; rev:1;)
alert udp any any -> any 123 (msg:"NTP DDoS Attempt"; dsize:>100; sid:1000004; rev:1;)
alert ip any any -> any any (msg:"Malformed Packet"; fragbits:M; sid:1000005; rev:1;)
"""
    with open("/etc/suricata/rules/custom.rules", "w") as f:
        f.write(rules)
    with open(suricata_conf, "a") as f:
        f.write("\nrule-files:\n  - custom.rules\n")
    run(["systemctl", "restart", "suricata"])

def harden_sysctl():
    sysctl_settings = """
# DDoS Hardening
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_max_syn_backlog = 20480
net.ipv4.tcp_synack_retries = 2
net.ipv4.tcp_fin_timeout = 15
net.ipv4.tcp_keepalive_time = 300
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv4.tcp_rfc1337 = 1
net.ipv4.ipfrag_time = 30
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1
net.ipv4.conf.all.proxy_arp = 0
net.ipv4.conf.default.proxy_arp = 0
kernel.randomize_va_space = 2
kernel.kptr_restrict = 2
kernel.sysrq = 0
fs.suid_dumpable = 0
net.ipv4.tcp_window_scaling = 1
net.ipv4.tcp_timestamps = 0
net.ipv4.tcp_sack = 0
net.ipv4.tcp_low_latency = 1
net.ipv4.tcp_retries2 = 5
"""
    with open("/etc/sysctl.conf", "a") as f:
        f.write(sysctl_settings)
    run(["sysctl", "-p"])

def deploy_iptables(interface):
    rules = [
        "iptables -A INPUT -i {} -p tcp --tcp-flags SYN,ACK,FIN,RST RST -j DROP".format(interface),
        "iptables -A INPUT -p tcp --tcp-flags ALL NONE -j DROP",
        "iptables -A INPUT -p tcp --tcp-flags ALL ALL -j DROP",
        "iptables -A INPUT -p tcp --tcp-flags SYN,FIN SYN,FIN -j DROP",
        "iptables -A INPUT -p tcp --tcp-flags SYN,RST SYN,RST -j DROP",
        "iptables -A INPUT -p tcp --tcp-flags FIN,RST FIN,RST -j DROP",
        "iptables -A INPUT -p tcp --tcp-flags ACK,FIN FIN -j DROP",
        "iptables -A INPUT -p tcp --tcp-flags ACK,PSH PSH -j DROP",
        "iptables -A INPUT -p tcp --tcp-flags ACK,URG URG -j DROP",
        "iptables -A INPUT -p udp --dport 53 -m u32 --u32 \"0>>22&0x3C@8=0x0000\" -j DROP",
        "iptables -A INPUT -p udp --dport 123 -m u32 --u32 \"0>>22&0x3C@8=0x0000\" -j DROP",
        "iptables -A INPUT -p tcp --tcp-flags SYN,ACK,FIN,RST SYN -m connlimit --connlimit-above 20 -j DROP"
    ]
    for rule in rules:
        run(rule.split())
    if shutil.which("netfilter-persistent"):
        run(["/usr/sbin/netfilter-persistent", "save"])
    elif shutil.which("service"):
        run(["service", "netfilter-persistent", "save"])
    else:
        run("netfilter-persistent save", shell=True)

def setup_ntpsec():
    run(["systemctl", "enable", "ntpsec"])
    run(["systemctl", "start", "ntpsec"])

def setup_ufw(interface):
    ufw_path = ensure_ufw_installed()
    run([ufw_path, "reset"])
    run([ufw_path, "default", "deny", "incoming"])
    run([ufw_path, "default", "allow", "outgoing"])
    run([ufw_path, "logging", "on"])
    run([ufw_path, "allow", "ssh"])
    run([ufw_path, "allow", "8388"])  # Shadowsocks port
    run([ufw_path, "enable"])

def deploy_shadowsocks_outline(server_ip):
    password = secrets.token_urlsafe(32)
    port = 8388
    method = "chacha20-ietf-poly1305"
    ss_conf = {
        "server": "0.0.0.0",
        "server_port": port,
        "local_port": 1080,
        "password": password,
        "timeout": 300,
        "method": method
    }
    with open("/etc/shadowsocks-libev/config.json", "w") as f:
        json.dump(ss_conf, f)
    run(["systemctl", "enable", "shadowsocks-libev"])
    run(["systemctl", "restart", "shadowsocks-libev"])
    ss_base = f"{method}:{password}"
    ss_base64 = base64.urlsafe_b64encode(ss_base.encode()).decode().rstrip("=")
    outline_url = f"ss://{ss_base64}@{server_ip}:{port}/?outline=1"
    print("Shadowsocks server deployed for Outline client.")
    print("Connect using this access key (Outline compatible):")
    print(outline_url)

def install_portsentry():
    ps_path = ensure_portsentry_installed()
    run(["systemctl", "enable", "portsentry"])
    run(["systemctl", "start", "portsentry"])
    print("Portsentry installed and enabled.")

def main():
    if os.geteuid() != 0:
        print("Must run as root!")
        sys.exit(1)
    print("Installing packages...")
    install_packages()
    print("Detecting public interface...")
    interface = get_public_interface()
    if not interface:
        print("Could not detect public interface. Please specify manually.")
        sys.exit(2)
    print(f"Using interface: {interface}")
    server_ip = get_server_ip(interface)
    print(f"Server IP for Shadowsocks: {server_ip}")
    print("Deploying Suricata IPS...")
    deploy_suricata(interface)
    print("Hardening sysctl...")
    harden_sysctl()
    print("Deploying iptables rules...")
    deploy_iptables(interface)
    print("Setting up ntpsec...")
    setup_ntpsec()
    print("Setting up ufw firewall (SSH, Shadowsocks allowed) and logging...")
    setup_ufw(interface)
    print("Deploying Shadowsocks server for Outline client...")
    deploy_shadowsocks_outline(server_ip)
    print("Installing and enabling portsentry (port scan protection)...")
    install_portsentry()
    print("Deployment complete.")

if __name__ == "__main__":
    main()
