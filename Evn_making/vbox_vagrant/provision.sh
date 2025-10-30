#!/usr/bin/env bash
ROLE="$1"
set -e

# Update and install base packages
sudo apt-get update -y
sudo apt-get install -y python3 python3-pip tcpdump tshark git vim apache2

# Install Zeek (only on monitor node)
if [ "$ROLE" = "monitor" ]; then
    sudo apt-get install -y zeek
    sudo mkdir -p /opt/captures
    sudo chown vagrant:vagrant /opt/captures
fi

# Ensure Apache is enabled for the server
if [ "$ROLE" = "server" ]; then
    sudo systemctl enable apache2
    sudo systemctl start apache2
    echo "<html><body>server</body></html>" | sudo tee /var/www/html/index.html
fi

# Install Python packages (common to all)
sudo pip3 install scapy pandas

# Create traffic generator script on client
if [ "$ROLE" = "client" ]; then
cat > /home/vagrant/traffic_gen.py <<'PY'
#!/usr/bin/env python3
from scapy.all import *
import sys, time, random

def http_get(target_ip, target_port=80, n=10, interval=0.2):
    for i in range(n):
        ip = IP(dst=target_ip)
        tcp = TCP(dport=target_port, sport=random.randint(1024,65535), flags="S")
        syn = sr1(ip/tcp, timeout=1, verbose=0)
        if syn is None:
            time.sleep(interval)
            continue
        ack = TCP(dport=target_port, sport=tcp.sport, flags="A", seq=syn.ack, ack=syn.seq+1)
        send(ip/ack, verbose=0)
        payload = "GET / HTTP/1.1\r\nHost: {}\r\nUser-Agent: traffic-gen\r\n\r\n".format(target_ip)
        send(ip/TCP(dport=target_port, sport=tcp.sport, flags="PA")/payload, verbose=0)
        time.sleep(interval)

def random_tcp_flood(target_ip, target_port=4444, n=50, interval=0.05):
    for _ in range(n):
        sport = random.randint(1024,65535)
        pkt = IP(dst=target_ip)/TCP(dport=target_port, sport=sport, flags="PA")/("X"*random.randint(20,200))
        send(pkt, verbose=0)
        time.sleep(interval)

if __name__ == '__main__':
    if len(sys.argv) < 3:
        print("Usage: traffic_gen.py <mode> <target_ip> [count]")
        sys.exit(1)
    mode = sys.argv[1]
    target = sys.argv[2]
    count = int(sys.argv[3]) if len(sys.argv) > 3 else 10
    if mode == "http":
        http_get(target, n=count)
    elif mode == "rndtcp":
        random_tcp_flood(target, n=count)
    else:
        print("Unknown mode")
PY

sudo chmod +x /home/vagrant/traffic_gen.py
sudo chown vagrant:vagrant /home/vagrant/traffic_gen.py
fi

echo "[+] Provision complete for role: $ROLE"
