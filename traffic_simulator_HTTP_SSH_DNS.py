#!/usr/bin/env python3
"""
traffic_sim_minimal.py

Silent traffic simulator. Hard-coded globals; prompts only for run length (minutes).
Performs randomized:
 - SSH: TCP connect to SSH_PORT on SSH_HOST (no auth)
 - HTTP: simple GET to HTTP_URL
 - DNS: UDP A query to DNS_SERVER for DNS_DOMAIN

No logging or printing while running.
"""

import random
import socket
import struct
import time
import urllib.request
from datetime import datetime, timedelta

# -----------------------------
# GLOBALS (edit these if desired)
HTTP_URL = "http://example.com"                                             #node 1
SSH_HOST = "127.0.0.1"                                                      #node 2
SSH_PORT = 22                                                               #node 2
DNS_SERVER = "8.8.8.8"                                                      #node 3
DNS_DOMAIN = "example.com"                                                  #node 3

# how long to wait between events (seconds)
MIN_INTERVAL = 0.5
MAX_INTERVAL = 4.0

# weights for choosing event type (http, ssh, dns)
OPTIONS = {"http": 3, "ssh": 1, "dns": 2}

# connection timeouts
HTTP_TIMEOUT = 5.0
SSH_TIMEOUT = 5.0
DNS_TIMEOUT = 3.0
# -----------------------------

def do_http(url, timeout=HTTP_TIMEOUT):
    try:
        with urllib.request.urlopen(url, timeout=timeout) as resp:
            # read a small chunk to complete the request but avoid large downloads
            resp.read(64)
    except Exception:
        pass  # silent on errors

def do_ssh_connect(host, port=SSH_PORT, timeout=SSH_TIMEOUT):
    s = None
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((host, port))
        # optionally attempt a tiny recv in case server sends a banner
        try:
            s.settimeout(0.5)
            _ = s.recv(64)
        except Exception:
            pass
    except Exception:
        pass
    finally:
        if s:
            try:
                s.close()
            except Exception:
                pass

def build_dns_query(name, qtype=1):
    tid = random.randint(0, 0xFFFF)
    flags = 0x0100  # standard query, recursion desired
    qdcount = 1
    header = struct.pack("!HHHHHH", tid, flags, qdcount, 0, 0, 0)
    parts = name.strip(".").split(".")
    qname = b"".join(struct.pack("B", len(p)) + p.encode() for p in parts) + b"\x00"
    question = qname + struct.pack("!HH", qtype, 1)  # IN class
    return tid, header + question

def do_dns_query(server, domain, timeout=DNS_TIMEOUT):
    s = None
    try:
        tid, q = build_dns_query(domain)
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(timeout)
        s.sendto(q, (server, 53))
        # try to receive a response (will raise on timeout)
        _ = s.recvfrom(512)
    except Exception:
        pass
    finally:
        if s:
            try:
                s.close()
            except Exception:
                pass

def pick_application(weights):
    names = list(weights.keys())
    w = [weights[name] for name in names]
    application = random.choices(names, weights=w, k=1)[0]
    return application
def main():
    try:
        raw = input("Run time in minutes: ").strip()
        minutes = float(raw)
    except Exception:
        return  # invalid input -> exit silently

    end_time = datetime.now() + timedelta(minutes=minutes)

    try:
        print(f"Running for {minutes}, will end on {end_time}")
        while datetime.now() < end_time:
            wait = random.uniform(MIN_INTERVAL, MAX_INTERVAL)
            time.sleep(wait)
            action = pick_application(OPTIONS)
            if action == "http":
                do_http(HTTP_URL)
            elif action == "ssh":
                do_ssh_connect(SSH_HOST, SSH_PORT)
            elif action == "dns":
                do_dns_query(DNS_SERVER, DNS_DOMAIN)
            # continue silently until time's up
    except KeyboardInterrupt:
        pass  # exit silently on Ctrl+C

if __name__ == "__main__":
    main()
