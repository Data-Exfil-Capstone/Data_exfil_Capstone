#!/usr/bin/env python3
"""
HUMAN TRAFFIC EMULATOR (Proxmox/Linux Compatible)

This script simulates a human employee's network footprint.
It differs from standard traffic generators by using:
1. Probabilistic State Machines (Users get 'stuck' in modes like Research or Admin work).
2. Gamma/Gaussian Distributions (Users don't wait exactly 10s; they wait 10s +/- variance).
3. Burstiness (Opening a webpage triggers multiple rapid requests, not just one).
4. Full Protocol Stacks (Uses native 'curl' and 'ssh' binaries for perfect handshakes).

REQUIREMENTS:
- Python 3
- SSH Key configured for the target (ssh-copy-id user@target)
"""

import subprocess
import time
import random
import sys
import signal
from datetime import datetime
import os
import argparse

# ==========================================
#              CONFIGURATION
# ==========================================

# TARGET CONFIGURATION
# ------------------------------------------
INTERNAL_SSH_IP = "192.168.197.20"   # <--- CHANGE THIS to your target server IP
SSH_USER = "node"                 # <--- CHANGE THIS to your SSH username

def setup_args():
    parser = argparse.ArgumentParser(description="Human Traffic Emulator")
    parser.add_argument(
                "-o", "--output",
                type=str,
                default="cap",
                help="prefix for ouput log file (default: cap)"
            )
    return parser.parse_args()

os.environ["SSLKEYLOGFILE"] = f"/home/node/traffic_gen/{setup_args().output}_tls_keys.log"

# SCHEDULE (24-Hour Format)
# ------------------------------------------
WORK_START_HOUR = 9    # Employee starts at 9:00 AM
WORK_END_HOUR = 17     # Employee leaves at 5:00 PM
LUNCH_HOUR = 12        # Lunch break (activity drops significantly)

# MODERN USER AGENTS (Updated for 2024/2025 Realism)
# ------------------------------------------
# We use specific versions to match real world OS/Browser combinations.
USER_AGENTS = [
    # Windows 10 + Chrome 121 (Standard Corporate Build)
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
   
    # macOS + Safari 17.2 (Standard Developer/Designer Machine)
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
   
    # Linux + Firefox 115 ESR (Standard Sysadmin Workstation)
    "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0",
   
    # Windows 11 + Edge (Corporate Alternative)
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0"
]

# SITE LIST FOR "RESEARCH" MODE
# ------------------------------------------
# A mix of technical docs, news, and social media to mimic a developer/admin.
EXTERNAL_SITES = [
    "https://github.com", "https://stackoverflow.com", "https://www.google.com",
    "https://www.reddit.com", "https://aws.amazon.com", "https://www.cnn.com",
    "https://www.wikipedia.org", "https://pypi.org", "https://news.ycombinator.com",
    "https://www.microsoft.com", "https://docs.docker.com"
]

# SSH COMMAND DICTIONARY
# ------------------------------------------
# These are harmless "discovery" commands a real human runs to check system status.
SSH_COMMANDS = [
    "whoami",
    "pwd",
    "ls -la /var/log",
    "df -h",             # Check disk space
    "free -m",           # Check memory
    "cat /etc/os-release",
    "uptime",
    "ps aux --sort=-%mem | head -n 5", # Check top memory processes
    "netstat -tuln",     # Check open ports
    "date"
]

# ==========================================
#           HELPER FUNCTIONS
# ==========================================

def log(msg):
    """Simple timestamped logger."""
    print(f"[{datetime.now().strftime('%H:%M:%S')}] {msg}")

def human_sleep(base_time, variance=0.5):
    """
    Simulates 'Think Time' using a Gaussian distribution.
   
    Why?
    A script waits exactly 10.0 seconds.
    A human waits 'about' 10 seconds.
   
    math.gauss(mu, sigma) creates a bell curve of sleep times centered on
    'base_time' with a spread defined by 'variance'.
    """
    sleep_time = random.gauss(base_time, base_time * variance)
    # Ensure we never sleep for a negative amount or 0
    sleep_time = max(1.5, sleep_time)
    time.sleep(sleep_time)

def is_working_hours():
    """
    Determines if the 'user' is currently at their desk based on the schedule.
    Returns: (Boolean is_active, String status_message)
    """
    now = datetime.now()
   
    # 1. Weekend Check (Saturday=5, Sunday=6)
    if now.weekday() >= 5:
        return False, "Weekend - User is off"
   
    # 2. Lunch Break Check (Variable probability)
    # 80% chance the user is away during the lunch hour
    if now.hour == LUNCH_HOUR:
        if random.random() < 0.8:
            return False, "Lunch Break - User is away"
           
    # 3. Standard Work Day Check
    if WORK_START_HOUR <= now.hour < WORK_END_HOUR:
        return True, "Working Hours - User is active"
       
    return False, "Off Hours - User is gone"

# ==========================================
#           TRAFFIC GENERATION
# ==========================================

def generate_dns_noise():
    """
    Simulates 'Pre-fetching'.
    Browsers often resolve DNS for links on a page before the user clicks them.
    We run a 'host' command to generate a DNS query without a TCP connection.
    """
    domain = random.choice(EXTERNAL_SITES).split("//")[-1]
    # We suppress output; we only care that the packet hits the wire.
    subprocess.run(["host", domain], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

def run_ssh_session():
    """
    Simulates a STATEFUL SSH session.
    A human doesn't just run one command and disconnect.
    They log in, run a few commands to troubleshoot, then disconnect.
    """
    # Randomly decide how many commands to run in this "session" (3 to 6)
    session_length = random.randint(3, 6)
    log(f"--- [STATE: SSH] User started admin session ({session_length} commands) ---")
   
    for i in range(session_length):
        cmd = random.choice(SSH_COMMANDS)
        log(f"    -> Running: '{cmd}'")
       
        # We use SSH options to prevent the script from hanging on prompts:
        # - ConnectTimeout: Fails fast if target is down.
        # - StrictHostKeyChecking=no: Auto-accepts new keys (crucial for automation).
        full_cmd = [
            "ssh", "-o", "ConnectTimeout=5",
            "-o", "StrictHostKeyChecking=no",
            "-o", "LogLevel=QUIET",
            f"{SSH_USER}@{INTERNAL_SSH_IP}", cmd
        ]
       
        # Execute the command
        result = subprocess.run(full_cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
       
        if result.returncode != 0:
            log(f"    [!] SSH Connection Failed. Check keys/IP.")
            break
           
        # "Think time" between typing commands (Humans read output before typing next cmd)
        human_sleep(4, 0.4)

def browse_external_web():
    """
    Simulates BURSTY web browsing.
    When you load a modern website, you don't make 1 request.
    You make 1 request (HTML), then several more (CSS, JS, Images),
    then you click a link.
    """
    site = random.choice(EXTERNAL_SITES)
    ua = random.choice(USER_AGENTS)
    log(f"--- [STATE: WEB] Browsing External: {site} ---")
   
    # 1. Main Page Load
    # curl args: -s (silent), -L (follow redirects), -A (User Agent), -m (max time)
    subprocess.run(["curl", "-s", "-L", "-A", ua, "-m", "10", site],
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
   
    # 2. Simulate "Reading" (Pause)
    # Reading a page takes longer (5-15 seconds)
    human_sleep(10, 0.5)
   
    # 3. The "Burst"
    # Simulate clicking 2-3 links on that same site or fetching resources
    burst_count = random.randint(1, 3)
    for _ in range(burst_count):
        # 30% chance to do a random DNS lookup during browsing (mimic background tabs)
        if random.random() < 0.3:
            generate_dns_noise()
           
        log(f"    -> Clicking internal link/resource on {site}...")
        subprocess.run(["curl", "-s", "-L", "-A", ua, "-m", "5", site],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
       
        # Short pause between clicks (fast browsing)
        human_sleep(3, 0.2)

# ==========================================
#           MAIN EXECUTION LOOP
# ==========================================

def main():
    log("=== STARTING DEVELOPED HUMAN TRAFFIC EMULATOR ===")
    log(f"Target: {INTERNAL_SSH_IP} | Protocol: SSH")
    log(f"Target: External Internet | Protocol: HTTPS")
   
    # Trap CTRL+C to exit cleanly
    def signal_handler(sig, frame):
        print("\n[!] User stopped the simulation.")
        sys.exit(0)
    signal.signal(signal.SIGINT, signal_handler)

    while True:
        try:
            # 1. Check Schedule
            active, status = is_working_hours()

            if not active:
                # If off hours, sleep for a long time (15 mins) and check again.
                # This reduces log noise and CPU usage during the "night".
                log(f"Status: {status}. Sleeping for 15 mins...")
                time.sleep(900)
                continue

            # 2. State Machine Decision
            # We don't just flip a coin; we decide a "mode" for the next few minutes.
            # 0.0 - 0.6: Research Mode (Web Browsing)
            # 0.6 - 0.9: Work Mode (SSH Admin Tasks)
            # 0.9 - 1.0: Coffee Break (Idle)
           
            state_roll = random.random()

            if state_roll < 0.6:
                # --- STATE: RESEARCH (WEB) ---
                # A user typically visits a few sites in a row (e.g. Google -> StackOverflow -> Github)
                # So we loop this action 2-4 times before reconsidering the state.
                session_duration = random.randint(2, 4)
                for _ in range(session_duration):
                    browse_external_web()
                    # Sleep between sites
                    human_sleep(8, 0.5)

            elif state_roll < 0.9:
                # --- STATE: WORK (SSH) ---
                run_ssh_session()

            else:
                # --- STATE: COFFEE BREAK ---
                # Sometimes people just walk away from the computer.
                break_time = random.randint(60, 300) # 1 to 5 minutes
                log(f"--- [STATE: IDLE] User taking a coffee break ({break_time}s) ---")
                time.sleep(break_time)
           
            # Short pause before the next "State Decision"
            human_sleep(5, 0.5)

        except Exception as e:
            # Catch network errors or glitches so the script doesn't crash
            log(f"[ERROR] An unexpected error occurred: {e}")
            time.sleep(10)

if __name__ == "__main__":
    main()
