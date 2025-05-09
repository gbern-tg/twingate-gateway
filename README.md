> ⚠️ **Experimental Project**  
> This is an experimental project and not officially supported by Twingate. Use at your own risk.

# 🛡️ Twingate Internet Gateway

A powerful Linux-based gateway solution that routes network traffic through Twingate's secure tunnel. Perfect for IoT devices, streaming boxes, and development kits that need secure internet access but have limited network configurability.

## Key Features
- 🔄 **DHCP Server**: Automatic IP assignment for connected devices
- 🛡️ **IP Filtering**: Granular access control with IP whitelisting
- 🌐 **Multi-Interface**: Support for both Ethernet and WiFi
- 🔒 **Secure Routing**: All traffic routed through Twingate's private tunnel
- 🖥️ **Cross-Platform**: Works on Ubuntu, Debian, Fedora, and CentOS
- 🏗️ **Flexible Deployment**: Run on VMs, physical hosts, or Raspberry Pi

## Use Cases
- 📺 Smart TVs & Streaming Devices (Roku, Fire TV, Chromecast)
- 🏠 IoT Devices & Smart Home Equipment
- 💻 Development Kits & Test Environments
- 🏢 Network Isolation & VLAN Management

---

## ⚙️ How It Works

![tg-gateway-arch](https://github.com/gbern-tg/twingate-gateway/blob/main/assets/twingate-gateway-arch.png "Twingate Gateway Architecture")

This script configures a Linux VM/host (Ubuntu, Debian, Fedora, or CentOS) to act as an Internet Gateway by:

- Setting up **DNSMasq** for DHCP and DNS.
- Configuring **iptables** for NAT, route forwarding, and optionally whitelisting client IPs for tighter access control.
- Installing and registering the **Twingate client**.

---

## 🖥️ System Requirements

- A **Linux machine** running Ubuntu/Debian/Fedora/CentOS, this can be a VM or something like Raspberry Pi.
- If a VM,
  - The VM can be hosted on a a **hypervisor** (e.g., Proxmox, Hyper-V, ESXi) or **macOS or Windows machine** using **virtualization software** (e.g., VirtualBox, UTM, VMWare, Parallels).
- For DHCP, the host/VM should have **at least 2 network interfaces**:
  - One for **internet (WAN)** access (bridged or NAT).
  - One for **local (LAN)** access (host-only or bridged to a LAN port).

> 💡 **Tip for VMs**: Bridged mode is ideal and recommended for the WAN interface so the VM is discoverable and reachable on the local network.

---

## 🔑 Prerequisites

1. A **Twingate Service Account**.
2. A valid `service-key.json` file from Twingate Admin Console.
3. Knowledge of your **local network subnet** (e.g., `192.168.0.0/24`).
4. (Optional) Desired DHCP IP range and gateway DNS (if DHCP is enabled).
5. Ability to run the script as root (`sudo` required).

---

## 🚀 Installation Instructions

### Option 1: Interactive Installation

1. **Clone this repository** (or download the script):
   ```bash
   git clone https://github.com/gbern-tg/twingate-gateway.git
   cd twingate-gateway
   ```

2. **Make the script executable**:
   ```bash
   chmod +x twingate-gateway.sh
   ```

3. **Run the script with root privileges**:
   ```bash
   sudo ./twingate-gateway.sh
   ```

4. **Follow the interactive prompts**, which will ask you to provide:
   - The network interface to use for **internet (WAN)**.
   - The subnet of your **local network**.
   - Path to your `service-key.json` file.
   - Whether to enable **DHCP** and configure LAN interface.
   - Whether to **restrict access** to specific IP addresses.

### Option 2: Non-Interactive Installation

You can also run the script non-interactively by setting environment variables before execution by setting in the script or setting the variables ahead of time:

```bash
# Required variables
export TWINGATE_SERVICE_KEY_FILE=/path/to/service-key.json
export WAN_INTERFACE=eth0
export LOCAL_NETWORK_SUBNET=192.168.1.0/24

# Optional variables
export ENABLE_DHCP=yes
export LAN_INTERFACE=eth1
export DHCP_RANGE=192.168.100.100,192.168.100.150,12h
export DHCP_GATEWAY=192.168.100.1
export DHCP_DNS=192.168.100.1
export ALLOW_SPECIFIC_IPS=yes
export ALLOWED_LAN_IPS=192.168.100.0/24
export ALLOWED_WAN_IPS=192.168.1.0/24

# Run the script
sudo ./twingate-gateway.sh
```

### Environment Variables Reference

| Variable | Required | Description | Example |
|----------|----------|-------------|---------|
| `TWINGATE_SERVICE_KEY_FILE` | Yes | Path to Twingate service key file | `/path/to/service-key.json` |
| `WAN_INTERFACE` | Yes | Network interface for internet access | `eth0` |
| `LOCAL_NETWORK_SUBNET` | Yes | Local network subnet | `192.168.1.0/24` |
| `ENABLE_DHCP` | No | Whether to enable DHCP | `yes` or `no` |
| `LAN_INTERFACE` | No* | Network interface for local network | `eth1` |
| `DHCP_RANGE` | No* | DHCP IP range and lease time | `192.168.100.100,192.168.100.150,12h` |
| `DHCP_GATEWAY` | No* | DHCP gateway IP | `192.168.100.1` |
| `DHCP_DNS` | No* | DHCP DNS IP | `192.168.100.1` |
| `ALLOW_SPECIFIC_IPS` | No | Whether to enable IP filtering | `yes` or `no` |
| `ALLOWED_LAN_IPS` | No* | Comma-separated list of allowed LAN IPs | `192.168.100.0/24` |
| `ALLOWED_WAN_IPS` | No* | Comma-separated list of allowed WAN IPs | `192.168.1.0/24` |

\* Required if `ENABLE_DHCP=yes` or `ALLOW_SPECIFIC_IPS=yes`

---

## 🌐 Example Configuration

| Setting                  | Example                     |
|--------------------------|-----------------------------|
| WAN Interface            | `eth0`                      |
| LAN Interface            | `eth1`                      |
| Local Subnet             | `192.168.1.0/24`            |
| DHCP Enabled             | `yes`                       |
| DHCP Range               | `192.168.100.100,192.168.100.150,12h` |
| DHCP Gateway             | `192.168.100.1`             |
| DHCP DNS                | `192.168.100.1`             |
| Whitelisted IPs (optional) | `192.168.1.5,192.168.100.100,192.168.100.105 -OR- 192.168.1.0/24,192.168.100.0/24` |

---

## 🔒 Optional IP Filtering

You can restrict access to the gateway by only allowing traffic from specific IPs. If enabled, only those IPs will be able to route traffic through Twingate. This applies to both WAN (local subnet host is on) & LAN interfaces (DHCP Range).

---

## 🛑 Notes

- **This script will stop and disable other DNS services** like `systemd-resolved`, `dnsmasq`, `named`, and `bind9`.
- All iptables and DNS configurations are backed up and replaced.
- It is highly recommended to **use a dedicated VM** for this purpose to avoid conflicts.

---

## 🧪 Tested On

- ✅ Ubuntu 20.04, 22.04
- ✅ Debian 11
- ✅ Fedora 38
- ✅ CentOS 8

---

## 📦 Packages Installed

- `dnsmasq`
- `iptables` / `iptables-persistent`
- `curl`
- `twingate` (via package manager)

---

## 🛠️ Troubleshooting

- **dnsmasq won't start**? Check `journalctl -u dnsmasq` or verify config at `/etc/dnsmasq.d/twingate-gateway.conf`.
- **No internet on LAN clients**? Confirm IP forwarding is enabled and that `iptables` rules are active.
- **Twingate interface (sdwan0) missing**? Ensure your `service-key.json` is valid and that the client successfully registers.
