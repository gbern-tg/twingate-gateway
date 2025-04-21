#!/bin/bash

# ============================================================
# Twingate Internet Gateway Configuration Script
# This script configures Ubuntu, Debian, CentOS or Fedora to function 
# as a Twingate Internet Gateway for the local network.
# ============================================================

# Prerequisites:
# 1. A Twingate Service Account.
# 2. A valid JSON Twingate configuration file (service-key.json).
# 3. The subnet of your local network.
# 4. This script should be run as root or with sudo.

# Example usage:
# sudo ./twingate-gateway.sh

# ============================================================
# Display Help/Usage
# ============================================================
if [ "$1" = "-h" ] || [ "$1" = "--help" ]; then
  echo "Usage: sudo ./twingate-gateway.sh"
  echo "This script will guide you through the configuration process."
  echo "You will be prompted for:"
  echo "  - Twingate service key file location"
  echo "  - Local network subnet"
  echo "  - Network interfaces configuration"
  echo "  - DHCP settings (optional)"
  echo "  - IP filtering settings (optional)"
  exit 0
fi

# ============================================================
# Check for Root/Sudo Privileges
# ============================================================
if [ "$EUID" -ne 0 ]; then
  echo "Please run as root or with sudo."
  exit 1
fi

# ============================================================
# Detect Network Interfaces
# ============================================================
echo "Detecting available network interfaces..."
WAN_INTERFACES=$(ip -o link show | awk -F': ' '{print $2}' | grep -E '^(eth|wlan|enp|ens)')
echo "Available interfaces:"
echo "$WAN_INTERFACES"

# ============================================================
# Prompt for Configuration
# ============================================================
echo "Please provide the following configuration details:"

# Prompt for WAN interface
while true; do
  read -p "Select the WAN interface that will be used to connect to the internet: " WAN_INTERFACE
  if echo "$WAN_INTERFACES" | grep -q "^$WAN_INTERFACE$"; then
    break
  else
    echo "Invalid interface. Please select from available interfaces."
  fi
  echo "==> WAN interface: $WAN_INTERFACE"
done

# Prompt for local network subnet
while true; do
  read -p "Enter the local network subnet that will be routed through Twingate (format: x.x.x.x/xx): " LOCAL_NETWORK_SUBNET
  if echo "$LOCAL_NETWORK_SUBNET" | grep -qE '^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/[0-9]{1,2}$'; then # Check if the subnet is valid
    break
  else
    echo "Invalid subnet format. Please use format x.x.x.x/xx"
  fi
  echo "==> Local network subnet: $LOCAL_NETWORK_SUBNET"
  WAN_BASE=$(echo "$LOCAL_NETWORK_SUBNET" | cut -d'/' -f1 | cut -d'.' -f1-3)
done

# Prompt for Twingate service key file
while true; do
  read -p "Enter the path to your Twingate service key file: " TWINGATE_SERVICE_KEY_FILE
  if [ -f "$TWINGATE_SERVICE_KEY_FILE" ]; then
    break
  else
    echo "File not found. Please provide a valid path."
  fi
  echo "==> Twingate service key file: $TWINGATE_SERVICE_KEY_FILE"
done

# Prompt for DHCP configuration
read -p "Do you want to enable DHCP? (yes/no) [no]: " ENABLE_DHCP
ENABLE_DHCP=${ENABLE_DHCP:-no}

if [[ "$ENABLE_DHCP" == "yes" ]]; then
  # Get available interfaces excluding the WAN interface
  echo "Available LAN interfaces (excluding WAN interface $WAN_INTERFACE):"
  LAN_INTERFACES=$(echo "$WAN_INTERFACES" | grep -v "^$WAN_INTERFACE$")
  echo "$LAN_INTERFACES"
  
  # Prompt for LAN interface only if DHCP is enabled
  while true; do
    read -p "Select the LAN interface for DHCP (interface providing the local network): " LAN_INTERFACE
    if echo "$LAN_INTERFACES" | grep -q "^$LAN_INTERFACE$"; then
      break
    else
      echo "Invalid interface. Please select from available LAN interfaces."
    fi
  done

  read -p "Enter DHCP range - this must be different from the WAN interface subnet (e.g., 192.168.100.100,192.168.100.150,12h): " DHCP_RANGE
  read -p "Enter DHCP gateway IP - this must be different from the WAN gateway IP (e.g., 192.168.100.1): " DHCP_GATEWAY
  read -p "Enter DHCP DNS IP - this must be different from the WAN DNS IP (e.g., 192.168.100.1): " DHCP_DNS
else
  # If no DHCP, use the same interface as WAN
  LAN_INTERFACE="$WAN_INTERFACE"
fi

# Prompt for IP filtering
read -p "Do you want to whitelist specific IPs to restrict access to Twingate? (yes/no) [no]: " ALLOW_SPECIFIC_IPS
# Set default to no if not specified
ALLOW_SPECIFIC_IPS=${ALLOW_SPECIFIC_IPS:-no}

if [[ "$ALLOW_SPECIFIC_IPS" == "yes" ]]; then
  if [[ "$ENABLE_DHCP" == "yes" ]]; then
    # Prompt for allowed LAN IPs
    echo "Enter comma-separated list of allowed IPs from your DHCP range ($DHCP_RANGE) individually or as a range"
    echo "Example: $DHCP_BASE.100,$DHCP_BASE.101, $DHCP_BASE.102-$DHCP_BASE.150"
    read -p "Allowed LAN IPs [$DHCP_RANGE]: " ALLOWED_LAN_IPS
    if [ -z "$ALLOWED_LAN_IPS" ]; then
      ALLOWED_LAN_IPS=$DHCP_RANGE
    fi
    # Prompt for allowed WAN IPs
    echo "Enter comma-separated list of allowed IPs from your network subnet individually or as a range"
    echo "Example: $WAN_BASE.100,$WAN_BASE.101,$WAN_BASE.102"
    read -p "Allowed WAN IPs [$LOCAL_NETWORK_SUBNET]: " ALLOWED_WAN_IPS
    if [ -z "$ALLOWED_WAN_IPS" ]; then
      ALLOWED_WAN_IPS=$LOCAL_NETWORK_SUBNET
    fi
  else
    echo "Enter comma-separated list of allowed IPs from your network subnet individually or as a range"
    echo "Example: $WAN_BASE.100,$WAN_BASE.101,$WAN_BASE.102"
    read -p "Allowed WAN IPs [$LOCAL_NETWORK_SUBNET]: " ALLOWED_WAN_IPS
    if [ -z "$ALLOWED_WAN_IPS" ]; then
      ALLOWED_WAN_IPS=$LOCAL_NETWORK_SUBNET
    fi
  fi
  #read -p "Allowed IPs: " ALLOWED_IPS
fi

# Get the main network interface IP address
MAIN_NETWORK_INTERFACE_IP=$(ip -4 addr show "$WAN_INTERFACE" | grep -oP '(?<=inet\s)\d+(\.\d+){3}')

# ============================================================
# Network Connectivity Check
# Purpose: Verify network connectivity before proceeding
# ============================================================
echo "Checking network connectivity..."

# Function to check DNS resolution
check_dns_resolution() {
  if ! ping -c 1 -W 1 8.8.8.8 &>/dev/null; then
    echo "ERROR: No network connectivity detected. Please check your network connection."
    exit 1
  fi
  
  # Check if DNS resolution is working
  if ! ping -c 1 -W 1 google.com &>/dev/null; then
    echo "WARNING: DNS resolution is not working. Attempting to fix..."
    # Try to use Google DNS temporarily
    echo "nameserver 127.0.0.1" > /etc/resolv.conf
    echo "nameserver 8.8.8.8" >> /etc/resolv.conf
  fi
}

# Check network connectivity before proceeding
check_dns_resolution

# ============================================================
# Stop and Disable Conflicting Services
# ============================================================
echo "Stopping and disabling conflicting services..."

# Function to safely stop and disable a service
stop_service() {
  local service=$1
  if systemctl is-active --quiet $service; then
    echo "Stopping $service..."
    sudo systemctl stop $service
    sudo systemctl disable $service
  fi
}

# Stop all DNS services
for service in bind9 named systemd-resolved dnsmasq; do
  stop_service $service
done

# Remove any existing DNS configurations
if [ -f "/etc/resolv.conf" ]; then
  echo "Backing up existing resolv.conf to /etc/resolv.conf.backup"
  cp /etc/resolv.conf /etc/resolv.conf.backup
fi

# Check if resolv.conf is a symlink and remove it if it is
if [ -L "/etc/resolv.conf" ]; then
  echo "Removing resolv.conf symlink..."
  sudo rm -f /etc/resolv.conf
fi

# Create minimal resolv.conf pointing to localhost since dnsmasq will handle DNS
if [ ! -f "/etc/resolv.conf" ] || [ ! -s "/etc/resolv.conf" ]; then
  echo "Creating minimal resolv.conf pointing to localhost..."
  sudo tee /etc/resolv.conf > /dev/null <<EOF
nameserver 127.0.0.1
EOF
fi

# Remove any existing dnsmasq configurations
if [ -d "/etc/dnsmasq.d" ]; then
  echo "Backing up existing dnsmasq configurations to /etc/dnsmasq.d.backup"
  mkdir -p /etc/dnsmasq.d.backup
  mv /etc/dnsmasq.d/* /etc/dnsmasq.d.backup/ 2>/dev/null || true
fi

# Remove any existing named configurations
if [ -d "/etc/bind" ]; then
  echo "Backing up existing bind configurations to /etc/bind.backup"
  mkdir -p /etc/bind.backup
  mv /etc/bind/* /etc/bind.backup/ 2>/dev/null || true
fi

# ============================================================
# Identify Package Manager and OS
# ============================================================
if [ -x "$(command -v apt-get)" ]; then
  PKG_MANAGER="apt-get"
  OS_TYPE="debian"
elif [ -x "$(command -v dnf)" ]; then
  PKG_MANAGER="dnf"
  OS_TYPE="fedora"
else
  echo "No supported package manager found. Exiting."
  exit 1
fi

# ============================================================
# Update Packages & Install Requirements
# ============================================================
echo "Updating packages and installing requirements..."

# Check network connectivity again before package operations
check_dns_resolution

if [ "$OS_TYPE" = "fedora" ]; then
  # Fedora/CentOS specific setup
  $PKG_MANAGER -y update
  $PKG_MANAGER install -y dnsmasq curl iptables-services
  sudo systemctl enable iptables && sudo systemctl start iptables
else
  # Debian/Ubuntu specific setup
  $PKG_MANAGER update -y
  $PKG_MANAGER install -y dnsmasq curl iptables iptables iptables-persistent
fi

# ============================================================
# Configure Network Interfaces
# ============================================================
echo "Configuring network interfaces..."

# Configure WAN interface
sudo ip link set "$WAN_INTERFACE" up

# Configure LAN interface
if [[ "$ENABLE_DHCP" == "yes" ]]; then
  sudo ip addr flush dev "$LAN_INTERFACE"
  sudo ip addr add "$DHCP_GATEWAY"/24 dev "$LAN_INTERFACE"
  sudo ip link set "$LAN_INTERFACE" up
fi

# ============================================================
# Configure DNSMasq
# ============================================================
echo "Configuring DNSMasq..."

# Get the main network interface IP address
MAIN_NETWORK_INTERFACE_IP=$(ip -4 addr show "$WAN_INTERFACE" | grep -oP '(?<=inet\s)\d+(\.\d+){3}')

# $DHCP_GATEWAY: Listen on the DHCP gateway IP (if DHCP is enabled)
if [[ "$ENABLE_DHCP" == "yes" ]]; then
  DHCP_GATEWAY_LISTEN="listen-address=127.0.0.1,$MAIN_NETWORK_INTERFACE_IP,$DHCP_GATEWAY"
else
  DHCP_GATEWAY_LISTEN="listen-address=127.0.0.1,$MAIN_NETWORK_INTERFACE_IP"
fi

# Create the dnsmasq configuration file
mkdir -p /etc/dnsmasq.d
cat <<EOF > /etc/dnsmasq.d/twingate-gateway.conf
# Interface Configuration
# ---------------------
# Specify which network interface dnsmasq should listen on
interface=$LAN_INTERFACE
bind-interfaces

# Listen Addresses
# ---------------
# 127.0.0.1: Listen on localhost for local DNS queries
# $MAIN_NETWORK_INTERFACE_IP: Listen on the WAN interface IP
# DHCP_GATEWAY_LISTEN: Dynamically set based on DHCP configuration
$DHCP_GATEWAY_LISTEN

# DNS Resolution Settings
# ---------------------
# domain-needed: Don't forward A or AAAA queries for plain names
# bogus-priv: Don't forward reverse lookups for private IP ranges
domain-needed
bogus-priv

# DNS Forwarding
# -------------
# Use system DNS servers for upstream resolution
resolv-file=/etc/resolv.conf
all-servers

# Twingate DNS Servers
# -------------------
# These are Twingate's DNS servers that will handle all DNS queries
# MANAGED BY TWINGATE - DO NOT EDIT
server=100.95.0.251
server=100.95.0.252
server=100.95.0.253
server=100.95.0.254
EOF

# Configure DHCP if enabled
if [[ "$ENABLE_DHCP" == "yes" ]]; then
cat <<EOF >> /etc/dnsmasq.d/twingate-gateway.conf

# DHCP Configuration
# -----------------
# dhcp-range: IP range to assign to clients, lease time
# dhcp-option=3: Router/gateway IP
# dhcp-option=6: DNS server IP
dhcp-range=$DHCP_RANGE
dhcp-option=3,$DHCP_GATEWAY
dhcp-option=6,$DHCP_DNS
listen-address=$DHCP_GATEWAY
EOF
fi

# ============================================================
# DNSMasq Service Management
# Purpose: Start and enable the DNSMasq service
# ============================================================
echo "Starting dnsmasq service..."
if ! systemctl restart dnsmasq; then
  echo "ERROR: Failed to start dnsmasq. Checking configuration..."
  echo "=== dnsmasq Configuration ==="
  cat /etc/dnsmasq.d/twingate-gateway.conf
  echo "=== dnsmasq Error Log ==="
  journalctl -u dnsmasq -n 50 --no-pager
  echo "=== Network Interfaces ==="
  ip addr show
  echo "=== Resolv.conf ==="
  cat /etc/resolv.conf
  echo "=== dnsmasq Status ==="
  systemctl status dnsmasq --no-pager
  exit 1
fi

# Verify dnsmasq is running
if ! systemctl is-active --quiet dnsmasq; then
  echo "ERROR: dnsmasq failed to start. Please check the configuration and logs above."
  exit 1
fi

systemctl enable dnsmasq

# ============================================================
# Configure NAT & IP Forwarding
# ============================================================
echo "Configuring NAT and IP forwarding..."

# ============================================================
# IPTables Initialization
# Purpose: Clear existing rules to start with a clean slate
# ============================================================
# Flush existing iptables rules
sudo iptables -F
sudo iptables -t nat -F

# ============================================================
# NAT Configuration
# Purpose: Set up Network Address Translation for the local network
# ============================================================
# Configure NAT rules for Twingate interface (sdwan0) for local network subnet and DHCP range
sudo iptables -t nat -A POSTROUTING -s "$LOCAL_NETWORK_SUBNET" -o sdwan0 -j MASQUERADE
sudo iptables -t nat -A POSTROUTING -s "$DHCP_RANGE" -o sdwan0 -j MASQUERADE

# Configure NAT rules for WAN interface (if not tunneled through Twingate)
sudo iptables -t nat -A POSTROUTING -s "$LOCAL_NETWORK_SUBNET" -o "$WAN_INTERFACE" -j MASQUERADE
sudo iptables -t nat -A POSTROUTING -s "$DHCP_RANGE" -o "$WAN_INTERFACE" -j MASQUERADE

# ============================================================
# Forwarding Rules
# Purpose: Allow traffic to flow between interfaces
# ============================================================
# Allow forwarding from LAN to WAN
#sudo iptables -A FORWARD -i "$LAN_INTERFACE" -o "$WAN_INTERFACE" -j ACCEPT

#sudo iptables -A FORWARD -i "$LAN_INTERFACE" -o "$WAN_INTERFACE" -s "$LOCAL_NETWORK_SUBNET" -j ACCEPT

# Allow forwarding from LAN to Twingate
#sudo iptables -A FORWARD -i "$LAN_INTERFACE" -o sdwan0 -j ACCEPT

# Allow established/related traffic from WAN to LAN
#sudo iptables -A FORWARD -i "$WAN_INTERFACE" -o "$LAN_INTERFACE" -m state --state ESTABLISHED,RELATED -j ACCEPT

# Allow established/related traffic from Twingate to LAN
#sudo iptables -A FORWARD -i sdwan0 -o "$LAN_INTERFACE" -m state --state ESTABLISHED,RELATED -j ACCEPT

# ============================================================
# IP Filtering Rules (if enabled)
# Purpose: Restrict access to specific IP addresses
# ============================================================

if [[ "$ALLOW_SPECIFIC_IPS" == "yes" ]]; then
  # Allow specific IPs to send traffic through the LAN interface
  if [[ -n "$ALLOWED_LAN_IPS" ]]; then
    echo "Allowing LAN IPs: $ALLOWED_LAN_IPS"
    # Convert comma-separated list to array
    IFS=',' read -r -a ALLOWED_LAN_IP_ARRAY <<< "$ALLOWED_LAN_IPS"
    # Allow only these IPs to send traffic through the LAN interface
    for ip in "${ALLOWED_LAN_IP_ARRAY[@]}"; do
      # Trim whitespace
      ip=$(echo "$ip" | xargs)
      # Check if this is an IP range
      if [[ "$ip" == *"-"* ]]; then
        # Split the range into start and end IPs
        start_ip=$(echo "$ip" | cut -d'-' -f1)
        end_ip=$(echo "$ip" | cut -d'-' -f2)
        # Convert IPs to integers for comparison
        start_int=$(echo "$start_ip" | awk -F. '{print ($1*256^3)+($2*256^2)+($3*256)+$4}')
        end_int=$(echo "$end_ip" | awk -F. '{print ($1*256^3)+($2*256^2)+($3*256)+$4}')
        # Add rules for each IP in the range
        for ((i=start_int; i<=end_int; i++)); do
          current_ip=$(printf "%d.%d.%d.%d\n" $((i>>24)) $((i>>16&255)) $((i>>8&255)) $((i&255)))
          sudo iptables -A FORWARD -s "$current_ip" -i "$LAN_INTERFACE" -o "$WAN_INTERFACE" -j ACCEPT
          sudo iptables -A FORWARD -s "$current_ip" -i "$LAN_INTERFACE" -o sdwan0 -j ACCEPT
        done
      else
        # Single IP case
        sudo iptables -A FORWARD -s "$ip" -i "$LAN_INTERFACE" -o "$WAN_INTERFACE" -j ACCEPT
        sudo iptables -A FORWARD -s "$ip" -i "$LAN_INTERFACE" -o sdwan0 -j ACCEPT
      fi
    done
  fi

  # Allow specific IPs to send traffic through the WAN interface
  if [[ "$ALLOW_SPECIFIC_IPS" == "yes" && -n "$ALLOWED_WAN_IPS" ]]; then
    # Convert comma-separated list to array
    IFS=',' read -r -a ALLOWED_WAN_IP_ARRAY <<< "$ALLOWED_WAN_IPS"
    # Allow only these IPs to send traffic through the WAN interface
    for ip in "${ALLOWED_WAN_IP_ARRAY[@]}"; do
      # Trim whitespace
      ip=$(echo "$ip" | xargs)
      # Check if this is an IP range
      if [[ "$ip" == *"-"* ]]; then
        # Split the range into start and end IPs
        start_ip=$(echo "$ip" | cut -d'-' -f1)
        end_ip=$(echo "$ip" | cut -d'-' -f2)
        # Convert IPs to integers for comparison
        start_int=$(echo "$start_ip" | awk -F. '{print ($1*256^3)+($2*256^2)+($3*256)+$4}')
        end_int=$(echo "$end_ip" | awk -F. '{print ($1*256^3)+($2*256^2)+($3*256)+$4}')
        # Add rules for each IP in the range
        for ((i=start_int; i<=end_int; i++)); do
          current_ip=$(printf "%d.%d.%d.%d\n" $((i>>24)) $((i>>16&255)) $((i>>8&255)) $((i&255)))
          sudo iptables -A FORWARD -s "$current_ip" -i "$WAN_INTERFACE" -o "$WAN_INTERFACE" -j ACCEPT
          sudo iptables -A FORWARD -s "$current_ip" -i "$WAN_INTERFACE" -o sdwan0 -j ACCEPT
        done
      else
        # Single IP case
        sudo iptables -A FORWARD -s "$ip" -i "$WAN_INTERFACE" -o "$WAN_INTERFACE" -j ACCEPT
        sudo iptables -A FORWARD -s "$ip" -i "$WAN_INTERFACE" -o sdwan0 -j ACCEPT
      fi
    done
  fi

  # Drop all others
  #sudo iptables -A FORWARD -i "$LAN_INTERFACE" -o sdwan0 -j DROP
  #sudo iptables -A INPUT -i "$LAN_INTERFACE" -j DROP
fi

# ============================================================
# IPTables Persistence
# Purpose: Save rules to survive reboots
# ============================================================
if [ "$OS_TYPE" = "fedora" ]; then
  # Fedora/CentOS: Save to /etc/sysconfig/iptables
  sudo iptables-save > /etc/sysconfig/iptables
else
  # Debian/Ubuntu: Save to /etc/iptables/rules.v4
  sudo iptables-save > /etc/iptables/rules.v4
  sudo systemctl restart iptables
fi

# ============================================================
# Enable IPv4 Forwarding
# ============================================================
echo "Enabling IPv4 forwarding..."

# Remove any existing entries (commented or uncommented)
sudo sed -i '/^#*net.ipv4.ip_forward=/d' /etc/sysctl.conf

# Add the new entry
echo "net.ipv4.ip_forward=1" | sudo tee -a /etc/sysctl.conf

# Apply the changes
sudo sysctl -p

# ============================================================
# Install Twingate Client
# ============================================================
echo "Installing Twingate client..."

# Check network connectivity before installing Twingate
check_dns_resolution

if [ "$OS_TYPE" = "debian" ]; then
  # Debian/Ubuntu specific setup
  echo "Adding Twingate's GPG key..."
  # Check if a key can be added without error, or return true if it fails (non-blocking and needs to be updated in the future)
  curl -fsSL https://packages.twingate.com/apt/gpg.key | \ gpg --dearmor | sudo tee /usr/share/keyrings/twingate-archive-keyring.gpg > /dev/null
  
  echo "Adding Twingate's repository..."
  # Check if the key exists
  if [ -f "/usr/share/keyrings/twingate-archive-keyring.gpg" ]; then
    # If the key exists, add the repository with the key
    echo "deb [signed-by=/usr/share/keyrings/twingate-archive-keyring.gpg] https://packages.twingate.com/apt/ /" | sudo tee /etc/apt/sources.list.d/twingate.list
  else
    # If the key does not exist, add the repository without the key
    echo "deb https://packages.twingate.com/apt/ /" | sudo tee /etc/apt/sources.list.d/twingate.list
  fi

  # Update package lists (ignore GPG errors)
  echo "Updating package lists..."
  sudo apt-get update || true

  # Install Twingate client
  echo "Installing Twingate package..."
  if ! sudo apt-get install -y twingate; then
    echo "WARNING: Failed to install Twingate client via apt. Trying alternative installation method..."
    if ! curl https://binaries.twingate.com/client/linux/install.sh | sudo bash; then
      echo "ERROR: Failed to install Twingate client. Please check your network connection."
      exit 1
    fi
  fi
else
  # Fedora/CentOS specific setup
  echo "Adding Twingate's repository..."
  sudo tee /etc/yum.repos.d/twingate.repo <<EOF
[twingate]
name=Twingate Repository
baseurl=https://packages.twingate.com/rpm/
enabled=1
gpgcheck=0
EOF

  # Update package lists
  echo "Updating package lists..."
  sudo dnf update -y || true

  # Install Twingate client
  echo "Installing Twingate package..."
  if ! sudo dnf install -y twingate; then
    echo "WARNING: Failed to install Twingate client via dnf. Trying alternative installation method..."
    if ! curl https://binaries.twingate.com/client/linux/install.sh | sudo bash; then
      echo "ERROR: Failed to install Twingate client. Please check your network connection."
      exit 1
    fi
  fi
fi

# Setup Twingate
if ! sudo twingate setup --headless "$TWINGATE_SERVICE_KEY_FILE"; then
  echo "ERROR: Failed to setup Twingate. Please check your service key and network connection."
  exit 1
fi

sudo systemctl enable --now twingate

# ============================================================
# Script Completion
# ============================================================
echo "✅ Twingate Internet Gateway configuration is complete."
echo "dnsmasq configuration saved to /etc/dnsmasq.d/twingate-gateway.conf"
echo "Please ensure your network interfaces are properly configured in your system's network configuration."
echo "Backups of existing configurations have been created in:"
echo "- /etc/resolv.conf.backup"
echo "- /etc/dnsmasq.d.backup"
echo "- /etc/bind.backup"
