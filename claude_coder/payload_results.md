# PayloadMAE Test Results

**Date:** *(fill in after running)*
**Model:** `payload_clean_tcp_withssl`
**Threshold:** *(set at training time — 99th percentile of training window scores)*

---

## How to generate these results

Run the following commands on the machine with the full decrypted PCAPs.
Replace paths with the actual PCAP locations on your system.

```bash
# Step 1 — Train the model on clean decrypted traffic
python payload_create_model_script.py \
    /path/to/clean_decrypted_tcp_withssl.pcap \
    payload_clean_tcp_withssl \
    --epochs 30

# Step 2 — Test against clean traffic (should classify as NORMAL)
python payload_test_model_script.py \
    payload_clean_tcp_withssl \
    /path/to/clean_decrypted_tcp_withssl.pcap \
    --verbose --plot --save-results payload_clean_results.json \
    --save-plot payload_clean_scores.png

# Step 3 — Test against dirty traffic (should classify as SUSPICIOUS/MALICIOUS)
python payload_test_model_script.py \
    payload_clean_tcp_withssl \
    /path/to/dirty_decrypted_tcp_withssl.pcap \
    --verbose --plot --save-results payload_dirty_results.json \
    --save-plot payload_dirty_scores.png
```

On Matt's machine the PCAP paths are:
- `/home/matt/Desktop/capstone/pcaps/capData/tcpO/clean_decrypted_tcp_withssl.pcap`
- `/home/matt/Desktop/capstone/pcaps/capData/tcpO/dirty_decrypted_tcp_withssl.pcap`

---

## Test Overview

*(Fill in after running — template below)*

| | Clean test | Dirty test |
|---|---|---|
| PCAP | `clean_decrypted_tcp_withssl.pcap` | `dirty_decrypted_tcp_withssl.pcap` |
| Packets loaded | | |
| Flows extracted | | |
| Flow windows scored | | |
| Anomalous windows | | |
| Anomalous flows | | |
| **Classification** | | |

---

## What to look for

### Comparing PayloadMAE vs FlowMAE on the same captures

Run both models on the same dirty PCAP and compare results side by side.
Key questions:

1. **Does PayloadMAE flag the same `192.168.199.244:5000` flows as FlowMAE?**
   If yes: both models agree on the exfil endpoint — strong signal.
   If no: investigate whether the payload content of those flows looked normal
   (i.e., was the exfiltrated data disguised to look like normal HTTP content?).

2. **Does PayloadMAE flag *additional* flows that FlowMAE missed?**
   These would be flows where timing/metadata looked normal but payload content
   was unusual — a more sophisticated attacker trying to blend into normal traffic
   patterns while still sending abnormal data.

3. **Does PayloadMAE produce *fewer* false positives on SSH flows?**
   FlowMAE flags SSH as anomalous because of irregular timing patterns.
   PayloadMAE may also flag SSH due to high entropy payloads, or may actually
   be *better* calibrated if SSH payloads are consistent enough to learn.

### Payload entropy as the key signal

The most important new feature is `payload_entropy`. In a dirty capture:
- **Exfiltrated plaintext** (keylogger output, dumped files) will show low entropy
  (~3–5 bits) and high printable_ratio — clearly different from the compressed/
  encrypted responses typical in normal HTTPS traffic
- **Binary exfil** will show high entropy (~7.5–8 bits) and low printable_ratio —
  similar to TLS but in an unusual flow context the model hasn't seen before
- **Base64-encoded exfil** shows medium entropy (~6 bits) and very high
  printable_ratio — recognizable by the model if training data never included this

### Score plot interpretation

The bar chart (`--plot` flag) shows per-window anomaly scores across all flow windows.
Red bars are above threshold. Look for:
- **Clusters of red bars** at the same flow (x-axis) — indicates repeated anomalous
  windows within a single flow, strong indicator
- **Isolated spikes** — single anomalous window in an otherwise clean flow, likely
  a false positive or one unusual packet in a legitimate connection
- **Score magnitude** — PayloadMAE scores may differ in absolute value from FlowMAE
  since it has a larger feature space (14 vs 8), but the relative ranking of flows
  should be meaningful

---

## Top Anomalous Flows

### Clean capture — top 10 anomalous flows

*(Fill in after running)*

| Score | Flow |
|---|---|
| | |

### Dirty capture — top 20 anomalous flows

*(Fill in after running)*

| Score | Flow |
|---|---|
| | |

---

## Score Plots

### Clean capture

*(Insert `payload_clean_scores.png` here after running)*

### Dirty capture

*(Insert `payload_dirty_scores.png` here after running)*

---

## FlowMAE vs PayloadMAE Comparison

*(Fill in after running both models on the same captures)*

| Metric | FlowMAE | PayloadMAE |
|---|---|---|
| Threshold | 0.820461 | |
| Clean — anomalous flows | 160 (4.0%) | |
| Clean — classification | NORMAL | |
| Dirty — anomalous flows | 649 (9.9%) | |
| Dirty — classification | SUSPICIOUS/MALICIOUS | |
| Top dirty flow score | 503.34 | |
| Top dirty flow endpoint | `192.168.199.244:5000` | |

Key difference to document: which flows does one model catch that the other misses?
This tells you whether payload content features add detection value beyond flow-level
metadata features alone.
