#!/usr/bin/env bash
ROLE="$1"
set -e

# Ensure home directory exists
if [ ! -d /home/vagrant ]; then
  mkdir -p /home/vagrant
  useradd -m vagrant || true
fi
chown -R vagrant:vagrant /home/vagrant

# update
sudo  dnf update -y
sudo dnf install -y python3 python3-pip tcpdump tshark git vim

# common python deps
sudo pip3 install scapy pandas

if [ "$ROLE" = "server" ]; then
  # small HTTP server
  sudo dnf install -y apache2
  sudo systemctl enable apache2
  sudo systemctl start apache2
  echo "<html><body>server</body></html>" | sudo tee /var/www/html/index.html
fi

if [ "$ROLE" = "monitor" ]; then
  # Install Zeek (Debian/Ubuntu quick install)
  # Use zeek package from package. This is a simple installer; adapt if you need newest version.
  sudo dnf install -y cmake make gcc g++ flex bison libpcap-dev libssl-dev python3-dev zlib1g-dev
  # quick install via apt (older but fine for capture)
  sudo dnf install -y zeek
  # create capture dir
  sudo mkdir -p /opt/captures
  sudo chown vagrant:vagrant /opt/captures
fi

# place traffic generator
cat > /home/vagrant/traffic_gen.py <<'PY'
#!/usr/bin/env python3
# Simple scapy traffic generator: HTTP GET bursts + random TCP flows
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
        ack = TCP(dport=target_port, sport=syn.sport, flags="A", seq=syn.ack, ack=syn.seq+1)
        send(ip/ack, verbose=0)
        # send a simple GET as raw payload
        payload = "GET / HTTP/1.1\r\nHost: {}\r\nUser-Agent: traffic-gen\r\n\r\n".format(target_ip)
        send(ip/TCP(dport=target_port, sport=syn.sport, flags="PA")/payload, verbose=0)
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

chmod +x /home/vagrant/traffic_gen.py
chown vagrant:vagrant /home/vagrant/traffic_gen.py

echo "Provision complete for role: $ROLE"
