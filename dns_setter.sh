#!/bin/bash

PRIMARY_DNS="192.168.1.105"
SECONDARY_DNS="8.8.8.8"

echo "[INFO] Setting DNS to $PRIMARY_DNS (primary) and $SECONDARY_DNS (backup)"

# Check if systemd-resolved is active
if systemctl is-active --quiet systemd-resolved; then
    echo "[INFO] systemd-resolved detected."

    # Update /etc/systemd/resolved.conf
    sudo bash -c "cat > /etc/systemd/resolved.conf" <<EOF
[Resolve]
DNS=$PRIMARY_DNS $SECONDARY_DNS
FallbackDNS=
DNSStubListener=yes
EOF

    echo "[INFO] Restarting systemd-resolved..."
    sudo systemctl restart systemd-resolved

else
    echo "[INFO] systemd-resolved NOT detected. Updating /etc/resolv.conf directly."

    # Backup resolv.conf
    sudo cp /etc/resolv.conf /etc/resolv.conf.bak

    sudo bash -c "cat > /etc/resolv.conf" <<EOF
nameserver $PRIMARY_DNS
nameserver $SECONDARY_DNS
EOF
fi

echo "[INFO] DNS configuration updated!"
