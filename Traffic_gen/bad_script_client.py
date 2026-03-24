import time
import requests
import random
from datetime import datetime

# --- CONFIGURATION ---
TARGET_URL = 'http://192.168.199.244:5000/endpoint'
WINDOW_SIZE = 300       # 5-minute transmission heartbeat
SUB_BURSTS = 4          # Sends data roughly every 75 seconds within that window

# --- BEHAVIORAL POOLS ---
# Higher entropy fragments to prevent pattern detection
COMPONENTS = {
    "subject": ["System admin ", "DevOps ", "The crawler ", "Kernel ", "Security policy "],
    "action": ["synchronized ", "intercepted ", "pushed ", "scaled ", "verified "],
    "target": ["the database node.", "the encrypted volume.", "the prod cluster.", "the firewall rules."],
    "noise": [" [BACKSPACE][BACKSPACE]", "...[Thinking]...", " [SHIFT_HOLD]", " :wq\n", " git push\n"]
}

def generate_dynamic_payload():
    """Generates a non-repeating, logically structured burst of data."""
    # Randomize the 'energy level' of the user for this window
    energy = random.choices(["high", "medium", "low"], weights=[20, 60, 20])[0]
   
    if energy == "high":
        count = random.randint(15, 25)
    elif energy == "medium":
        count = random.randint(8, 14)
    else:
        count = random.randint(2, 5)

    payload = ""
    for _ in range(count):
        sentence = (f"{random.choice(COMPONENTS['subject'])}"
                    f"{random.choice(COMPONENTS['action'])}"
                    f"{random.choice(COMPONENTS['target'])}")
       
        # Add human imperfections
        if random.random() < 0.2:
            sentence += random.choice(COMPONENTS['noise'])
       
        payload += sentence + " "
   
    return payload

def start_perpetual_stream():
    print(f"[*] Initializing Perpetual Stream to {TARGET_URL}")
    print("[*] Mode: Indefinite | Interval: 300s | Press Ctrl+C to terminate.")

    cycle_count = 0
   
    while True: # Running indefinitely
        cycle_count += 1
        window_start = time.time()
       
        # Determine the total payload for this 5-minute block
        full_payload = generate_dynamic_payload()
       
        # Break it into sub-bursts to simulate 'live' typing flushes
        chunks = [full_payload[i:i + len(full_payload)//SUB_BURSTS]
                  for i in range(0, len(full_payload), len(full_payload)//SUB_BURSTS)]

        for i, chunk in enumerate(chunks):
            sub_start = time.time()
            try:
                # Mimic a real browser environment
                headers = {
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                    'Accept': 'application/json',
                    'Content-Type': 'application/json'
                }
               
                response = requests.post(
                    TARGET_URL,
                    json={'data': chunk, 'cycle': cycle_count, 'sub': i+1},
                    headers=headers,
                    timeout=20
                )
               
                print(f"[{datetime.now().strftime('%H:%M:%S')}] Cycle {cycle_count} Sub {i+1} | {len(chunk)} chars sent.")
           
            except requests.exceptions.RequestException as e:
                # Silently log errors to prevent console spam, then keep going
                print(f"[!] Connection issue at {datetime.now().strftime('%H:%M:%S')}. Retrying in next window...")
           
            # Sub-burst timing: spread chunks evenly across the 5 minutes
            time.sleep(max(1, (WINDOW_SIZE / SUB_BURSTS) - (time.time() - sub_start)))

        # Final drift compensation for the main window
        elapsed = time.time() - window_start
        if elapsed < WINDOW_SIZE:
            time.sleep(WINDOW_SIZE - elapsed)

if __name__ == "__main__":
    try:
        start_perpetual_stream()
    except KeyboardInterrupt:
        print("\n[!] Shutdown signal received. Ending stream safely.")
