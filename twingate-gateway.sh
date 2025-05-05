#!/bin/bash

# ============================================================
# Twingate Internet Gateway Configuration Script
# This script configures Ubuntu, Debian, CentOS or Fedora to function 
# as a Twingate Internet Gateway for the local network.
# ============================================================

# ============================================================
# Prerequisites
# ============================================================
# 1. Operating System Requirements:
#    - Ubuntu 20.04 LTS or newer
#    - Debian 10 or newer
#    - CentOS 8 or newer
#    - Fedora 32 or newer
#
# 2. Network Requirements:
#    - At least two network interfaces (WAN and LAN)
#    - WAN interface with internet connectivity
#    - LAN interface for local network
#
# 3. Twingate Requirements:
#    - A valid Twingate account
#    - A Twingate Service Account
#    - A valid JSON Twingate configuration file (service-key.json)
#
# 4. System Requirements:
#    - Root or sudo privileges
#    - At least 1GB RAM
#    - At least 10GB disk space
#    - System with IP forwarding capability
#
# 5. Network Configuration:
#    - Local network subnet (e.g., 192.168.210.0/24)
#    - DHCP configuration (if enabled)
#    - DNS configuration
#
# Note: This script will:
# - Configure network interfaces
# - Set up DNSMasq for DNS and DHCP
# - Configure NAT and IP forwarding
# - Install and configure Twingate client
# - Set up IP filtering (optional)
#
# Environment Variables (can be set before running the script):
# TWINGATE_SERVICE_KEY_FILE - Path to Twingate service key file
# WAN_INTERFACE - WAN interface (e.g., wlan0)
# LAN_INTERFACE - LAN interface (e.g., eth0)
# LOCAL_NETWORK_SUBNET - Local network subnet (e.g., 192.168.210.0/24)
# ENABLE_DHCP - Whether to enable DHCP (yes/no)
# DHCP_RANGE - DHCP range (e.g., 192.168.100.100,192.168.100.150,12h)
# DHCP_GATEWAY - DHCP gateway IP (e.g., 192.168.100.1)
# DHCP_DNS - DHCP DNS IP (e.g., 192.168.100.1)
# ALLOW_SPECIFIC_IPS - Whether to enable IP filtering (yes/no)
# ALLOWED_LAN_IPS - Comma-separated list of allowed LAN IPs
# ALLOWED_WAN_IPS - Comma-separated list of allowed WAN IPs

# ============================================================
# (OPTIONAL) Configurations - uncomment to use
# ============================================================

# Example usage: Set environment variables
#export TWINGATE_SERVICE_KEY_FILE=$HOME/twingate-gateway/service-key.json
#export WAN_INTERFACE=wlan0
#export LAN_INTERFACE=eth0
#export LOCAL_NETWORK_SUBNET=192.168.1.0/24
#export ENABLE_DHCP=yes
#export DHCP_RANGE=192.168.100.100,192.168.100.150,12h
#export DHCP_GATEWAY=192.168.100.1
#export DHCP_DNS=192.168.100.1
#export ALLOW_SPECIFIC_IPS=yes
#export ALLOWED_LAN_IPS=192.168.100.0/24
#export ALLOWED_WAN_IPS=192.168.210.0/24

# Example usage: Run the script
# sudo ./twingate-gateway.sh

# ============================================================
# Display Help/Usage
# ============================================================
if [ "$1" = "-h" ] || [ "$1" = "--help" ]; then
  echo "Usage: sudo ./twingate-gateway.sh"
  echo "This script will guide you through the configuration process."
  echo ""
  echo "You can run this script in two ways:"
  echo ""
  echo "1. Interactive Mode (default):"
  echo "   Just run the script and follow the prompts"
  echo ""
  echo "2. Non-Interactive Mode:"
  echo "   Set environment variables before running:"
  echo ""
  echo "   Required variables:"
  echo "   TWINGATE_SERVICE_KEY_FILE=/path/to/service-key.json"
  echo "   WAN_INTERFACE=eth0"
  echo "   LOCAL_NETWORK_SUBNET=192.168.1.0/24"
  echo ""
  echo "   Optional variables:"
  echo "   ENABLE_DHCP=yes"
  echo "   LAN_INTERFACE=eth1"
  echo "   DHCP_RANGE=192.168.100.100,192.168.100.150,12h"
  echo "   DHCP_GATEWAY=192.168.100.1"
  echo "   DHCP_DNS=192.168.100.1"
  echo "   ALLOW_SPECIFIC_IPS=yes"
  echo "   ALLOWED_LAN_IPS=192.168.100.0/24"
  echo "   ALLOWED_WAN_IPS=192.168.1.0/24"
  echo ""
  echo "For more details, see the README.md file."
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
# Set noninteractive mode for all prompts
# ============================================================
export DEBIAN_FRONTEND=noninteractive

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

# Prompt for WAN interface
if [ -z "$WAN_INTERFACE" ]; then
  while true; do
    read -p "Select the WAN interface that will be used to connect to the internet: " WAN_INTERFACE
    if echo "$WAN_INTERFACES" | grep -q "^$WAN_INTERFACE$"; then
      break
    else
      echo "Invalid interface. Please select from available interfaces."
    fi
  done
else
  echo "Using WAN interface from environment: $WAN_INTERFACE"
fi

# Prompt for local network subnet
if [ -z "$LOCAL_NETWORK_SUBNET" ]; then
  while true; do
    read -p "Enter the local network subnet that will be routed through Twingate (format: x.x.x.x/xx): " LOCAL_NETWORK_SUBNET
    if echo "$LOCAL_NETWORK_SUBNET" | grep -qE '^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/[0-9]{1,2}$'; then
      break
    else
      echo "Invalid subnet format. Please use format x.x.x.x/xx"
    fi
  done
else
  echo "Using local network subnet from environment: $LOCAL_NETWORK_SUBNET"
fi

# Prompt for Twingate service key file
if [ -z "$TWINGATE_SERVICE_KEY_FILE" ]; then
  while true; do
    read -p "Enter the path to your Twingate service key file: " TWINGATE_SERVICE_KEY_FILE
    if [ -f "$TWINGATE_SERVICE_KEY_FILE" ]; then
      break
    else
      echo "File not found. Please provide a valid path."
    fi
  done
else
  echo "Using Twingate service key file from environment: $TWINGATE_SERVICE_KEY_FILE"
fi

# Prompt for DHCP configuration
if [ -z "$ENABLE_DHCP" ]; then
  read -p "Do you want to enable DHCP? (yes/no) [no]: " ENABLE_DHCP
  ENABLE_DHCP=${ENABLE_DHCP:-no}
else
  echo "Using DHCP configuration from environment: $ENABLE_DHCP"
fi

if [[ "$ENABLE_DHCP" == "yes" ]]; then
  # Get available interfaces excluding the WAN interface
  echo "Available LAN interfaces (excluding WAN interface $WAN_INTERFACE):"
  LAN_INTERFACES=$(echo "$WAN_INTERFACES" | grep -v "^$WAN_INTERFACE$")
  echo "$LAN_INTERFACES"
  
  # Prompt for LAN interface only if DHCP is enabled
  if [ -z "$LAN_INTERFACE" ]; then
    while true; do
      read -p "Select the LAN interface for DHCP (interface providing the local network): " LAN_INTERFACE
      if echo "$LAN_INTERFACES" | grep -q "^$LAN_INTERFACE$"; then
        break
      else
        echo "Invalid interface. Please select from available LAN interfaces."
      fi
    done
  else
    echo "Using LAN interface from environment: $LAN_INTERFACE"
  fi

  if [ -z "$DHCP_RANGE" ]; then
    read -p "Enter DHCP range - this must be different from the WAN interface subnet (e.g., 192.168.100.100,192.168.100.150,12h): " DHCP_RANGE
  else
    echo "Using DHCP range from environment: $DHCP_RANGE"
  fi

  if [ -z "$DHCP_GATEWAY" ]; then
    read -p "Enter DHCP gateway IP - this must be different from the WAN gateway IP (e.g., 192.168.100.1): " DHCP_GATEWAY
  else
    echo "Using DHCP gateway from environment: $DHCP_GATEWAY"
  fi

  if [ -z "$DHCP_DNS" ]; then
    read -p "Enter DHCP DNS IP - this must be different from the WAN DNS IP (e.g., 192.168.100.1): " DHCP_DNS
  else
    echo "Using DHCP DNS from environment: $DHCP_DNS"
  fi
else
  # If no DHCP, use the same interface as WAN
  LAN_INTERFACE="$WAN_INTERFACE"
fi

# Prompt for IP filtering
if [ -z "$ALLOW_SPECIFIC_IPS" ]; then
  read -p "Do you want to whitelist specific IPs to restrict access to Twingate? (yes/no) [no]: " ALLOW_SPECIFIC_IPS
  ALLOW_SPECIFIC_IPS=${ALLOW_SPECIFIC_IPS:-no}
else
  echo "Using IP filtering configuration from environment: $ALLOW_SPECIFIC_IPS"
fi

if [[ "$ALLOW_SPECIFIC_IPS" == "yes" ]]; then
  if [[ "$ENABLE_DHCP" == "yes" ]]; then
    if [ -z "$ALLOWED_LAN_IPS" ]; then
      echo "Enter comma-separated list of allowed IPs from your DHCP range ($DHCP_RANGE) individually or as a range"
      echo "Example: $DHCP_BASE.100,$DHCP_BASE.101, $DHCP_BASE.102-$DHCP_BASE.150"
      read -p "Allowed LAN IPs [$DHCP_RANGE]: " ALLOWED_LAN_IPS
      if [ -z "$ALLOWED_LAN_IPS" ]; then
        ALLOWED_LAN_IPS=$DHCP_RANGE
      fi
    else
      echo "Using allowed LAN IPs from environment: $ALLOWED_LAN_IPS"
    fi

    if [ -z "$ALLOWED_WAN_IPS" ]; then
      echo "Enter comma-separated list of allowed IPs from your network subnet individually or as a range"
      echo "Example: $WAN_BASE.100,$WAN_BASE.101,$WAN_BASE.102"
      read -p "Allowed WAN IPs [$LOCAL_NETWORK_SUBNET]: " ALLOWED_WAN_IPS
      if [ -z "$ALLOWED_WAN_IPS" ]; then
        ALLOWED_WAN_IPS=$LOCAL_NETWORK_SUBNET
      fi
    else
      echo "Using allowed WAN IPs from environment: $ALLOWED_WAN_IPS"
    fi
  else
    if [ -z "$ALLOWED_WAN_IPS" ]; then
      echo "Enter comma-separated list of allowed IPs from your network subnet individually or as a range"
      echo "Example: $WAN_BASE.100,$WAN_BASE.101,$WAN_BASE.102"
      read -p "Allowed WAN IPs [$LOCAL_NETWORK_SUBNET]: " ALLOWED_WAN_IPS
      if [ -z "$ALLOWED_WAN_IPS" ]; then
        ALLOWED_WAN_IPS=$LOCAL_NETWORK_SUBNET
      fi
    else
      echo "Using allowed WAN IPs from environment: $ALLOWED_WAN_IPS"
    fi
  fi
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
  # Ensure debconf is installed
  if ! command -v debconf-set-selections &> /dev/null; then
    $PKG_MANAGER install -y debconf
  fi

  # Configure unattended upgrades to prevent prompts
  #echo '* libraries/restart-without-asking boolean true' | debconf-set-selections
  #echo 'Dpkg::Options::="--force-confdef";' > /etc/apt/apt.conf.d/local
  #echo 'Dpkg::Options::="--force-confold";' >> /etc/apt/apt.conf.d/local

  # Update package lists
  $PKG_MANAGER update -y

  # Install iptables-persistent without prompts
  echo iptables-persistent iptables-persistent/autosave_v4 boolean true | debconf-set-selections
  echo iptables-persistent iptables-persistent/autosave_v6 boolean true | debconf-set-selections
  $PKG_MANAGER install -y dnsmasq curl iptables iptables-persistent

  # Ensure iptables-persistent is enabled
  systemctl enable netfilter-persistent
  systemctl start netfilter-persistent
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

# DNS TTL Settings
# --------------
# Set short TTL (60 seconds) for all DNS records
min-cache-ttl=60
max-cache-ttl=60
local-ttl=60
neg-ttl=60
auth-ttl=60
max-ttl=60

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
# IP Filtering Rules (if enabled) and Forwarding Rules
# Purpose: Restrict access to specific IP addresses (if enabled) and allow forwarding to specific IPs (if enabled)
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

  # Drop all other traffic attempting to pass through the LAN or WAN interfaces to the sdwan0 interface
  sudo iptables -A FORWARD -i "$LAN_INTERFACE" -o sdwan0 -j DROP
  sudo iptables -A FORWARD -i "$WAN_INTERFACE" -o sdwan0 -j DROP

# (OPTIONAL) If ALLOW_SPECIFIC_IPS is not enabled, allow all traffic through to sdwan0 (more scoped down)
#else 
  # Allow all traffic through to sdwan0
  #sudo iptables -A FORWARD -i "$LAN_INTERFACE" -o sdwan0 -j ACCEPT
  #sudo iptables -A FORWARD -i "$WAN_INTERFACE" -o sdwan0 -j ACCEPT

  # Allow all traffic through to LAN interface
  #sudo iptables -A FORWARD -i "$WAN_INTERFACE" -o "$LAN_INTERFACE" -j ACCEPT

  # Allow all traffic through to WAN interface
  #sudo iptables -A FORWARD -i "$LAN_INTERFACE" -o "$WAN_INTERFACE" -j ACCEPT
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
# Display Current IPTables Rules
# ============================================================
echo "Current IPTables Rules:"
echo "======================"
echo "Filter Table Rules:"
sudo iptables -L -v -n
echo -e "\nNAT Table Rules:"
sudo iptables -t nat -L -v -n
echo -e "\nMangle Table Rules:"
sudo iptables -t mangle -L -v -n

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
