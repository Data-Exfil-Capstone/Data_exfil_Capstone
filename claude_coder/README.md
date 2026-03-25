# Network Anomaly Detection — Autoencoder Suite

A machine learning system for detecting anomalous network traffic and data exfiltration attempts. Three separate pipelines are available depending on your input data and detection needs.

| Pipeline | Input | Anomaly unit | Status |
|---|---|---|---|
| **FlowMAE** | `.pcap` | Per flow | **Active** |
| **PayloadMAE** | `.pcap` (decrypted) | Per flow | **Active** |
| PCAP Autoencoder | `.pcap` | Per packet | Legacy (`legacy/`) |
| CSV Autoencoder | `.csv` | Per packet | Legacy (`legacy/`) |

---

## How It Works

### PCAP / CSV Autoencoders

1. **Train** on normal/benign traffic — the autoencoder learns to reconstruct normal packet features with low error
2. **Test** against new traffic — packets that reconstruct poorly are flagged as anomalous
3. Traffic is classified as **SUSPICIOUS** if >10% of packets are anomalous

### FlowMAE (Masked Autoencoder)

1. Packets are grouped into flows by 5-tuple `(src_ip, src_port, dst_ip, dst_port, proto)`
2. Each flow becomes a sequence of packet feature vectors windowed into 32-packet chunks
3. During training, 40% of packet slots are randomly masked — the Transformer must reconstruct them from context, learning what a normal flow conversation looks like over time
4. **Test** against new traffic — flows whose masked packets reconstruct poorly are flagged
5. Traffic is classified as **SUSPICIOUS** if >5% of flows are anomalous

FlowMAE catches patterns that per-packet models miss: beaconing (regular inter-arrival timing), slow-drip exfiltration (many small payloads), directional asymmetry (all upload, no download), and repeated connections to unusual internal endpoints.

---

## Project Structure

```
claude_coder/
│
├── ── FlowMAE (active) ──────────────────────────────────────────────
├── flow_mae_lib.py              # Core library (FlowMAE class)
├── flow_create_model_script.py  # Create and train directly from PCAP
├── flow_train_model_script.py   # Continue training with more PCAP data
├── flow_test_model_script.py    # Test traffic — reports anomalous flows
├── flow_results.md              # Test results and analysis
├── README.md
│
├── models/                      # Active FlowMAE model files
│   ├── flow_clean_tcp_withssl_flowmae.h5
│   ├── flow_clean_tcp_withssl_flowmae.weights.h5
│   ├── flow_clean_tcp_withssl_flowmae_config.pkl
│   ├── README.md
│   └── legacy/                  # Old autoencoder model files
│
└── legacy/                      # Old pipelines (PCAP + CSV autoencoders)
    ├── pcap_autoencoder_lib.py
    ├── create_model_script.py
    ├── train_model_script.py
    ├── test_model_script.py
    ├── csv_autoencoder_lib.py
    ├── csv_create_model_script.py
    ├── csv_train_model_script.py
    ├── csv_test_model_script.py
    ├── mae_sketches.py
    └── testers/                 # Old test PCAPs and result plots
```

---

## Requirements

```bash
pip install tensorflow scapy scikit-learn numpy pandas matplotlib
```

---

## FlowMAE

Groups packets into flows by 5-tuple and runs a Transformer Masked Autoencoder over each flow's packet sequence. Anomaly scoring is **per-flow** rather than per-packet.

### Architecture

```
PCAP → group by 5-tuple → 32-packet windows × 8 features
     → linear projection → 32-dim
     → positional encoding
     → 2× Transformer encoder blocks (4 heads, FF=64)
     → Dense(8) reconstruction
     → MSE loss on masked (40%) positions only
```

**Features per packet (8):**

| Feature | Description |
|---|---|
| `inter_arrival_time` | Seconds since previous packet in this flow |
| `packet_length` | Total wire length in bytes |
| `ip_ttl` | IP time-to-live |
| `ip_flags` | IP flags (DF, MF) |
| `tcp_flags` | TCP control flags (0 for non-TCP) |
| `tcp_window` | TCP receive window (0 for non-TCP) |
| `payload_len` | Application payload bytes |
| `direction` | 0 = initiator→responder, 1 = responder→initiator |

### Create a new model

```bash
python flow_create_model_script.py benign.pcap my_model
```

| Flag | Default | Description |
|---|---|---|
| `--epochs` | 30 | Max training epochs (early stopping applies) |
| `--batch-size` | 32 | Batch size |
| `--max-flow-len` | 32 | Packets per flow window |
| `--min-flow-len` | 4 | Minimum packets to keep a flow |
| `--mask-ratio` | 0.40 | Fraction of packet slots masked during training |
| `--d-model` | 32 | Transformer hidden dimension |
| `--num-layers` | 2 | Number of Transformer encoder blocks |

### Continue training

```bash
python flow_train_model_script.py my_model more_benign.pcap [--output-name new_name]
```

### Test / detect

```bash
python flow_test_model_script.py my_model suspect.pcap [--verbose] [--plot] [--save-results out.json]
```

Output reports anomalous flows by 5-tuple with individual scores. Exit codes: `0` = normal, `1` = suspicious/malicious, `2` = error.

### Test results

See `flow_results.md` for a full analysis of the model tested against clean and dirty PCAPs.
Key finding: the dirty capture was correctly flagged with 649/6543 flows (9.9%) anomalous,
with the top anomalies concentrated on `192.168.199.244:5000` — the suspected exfiltration endpoint.

---

---

## FlowMAE vs Normal Autoencoder

### What a normal autoencoder does

A normal autoencoder takes an input, compresses it through a narrow bottleneck, then reconstructs it. The anomaly score is simply how badly it reconstructed that single input.

```
packet features → [64 → 32 → 8] → [32 → 64] → reconstructed features
                      encoder          decoder

anomaly score = MSE(input, reconstruction)
```

It processes one packet at a time with no awareness of what came before or after.

### Three key differences in FlowMAE

**1. Sequences, not individual samples**

FlowMAE sees an entire flow — 32 packets in order from the same TCP/UDP conversation. It can learn relationships like: *"after a SYN and SYN-ACK, the next packet should have ACK flags and a small payload"* or *"inter-arrival time stays consistent in this kind of flow."* A normal autoencoder never sees packets in relation to each other.

**2. Masking instead of bottleneck compression**

A normal autoencoder prevents copying via a narrow bottleneck. FlowMAE uses a different mechanism — it hides 40% of the input and forces the model to reconstruct the missing pieces from surrounding context.

```
Normal AE:  [full input] → tiny bottleneck → [reconstructed full input]
                           compression forces learning

FlowMAE:    [pkt1, ???, pkt3, ???, pkt5 ...] → reconstruct ???
                           missing context forces learning
```

This is the same idea as BERT (predict masked words) — the model must understand relationships between packets to fill in the blanks. It cannot just memorize individual packets.

**3. Transformer attention instead of dense layers**

A Transformer lets every packet in the window directly attend to every other packet when deciding how to reconstruct itself. Dense layers have no mechanism to compare one packet to another.

```
Normal AE:  packet → layers → bottleneck → layers → output
            (no awareness of other packets)

FlowMAE:    [pkt1, pkt2, pkt3 ...] → attention across all packets → reconstruct
            (each packet informed by every other packet in the flow)
```

### Why this matters for exfil detection

| Pattern | Normal AE | FlowMAE |
|---|---|---|
| Unusual packet header (bad TTL, weird flags) | Catches it | Catches it |
| Beaconing (packets every 30s like clockwork) | Misses — one packet looks normal | Catches — inter-arrival regularity is learned |
| Slow drip (many tiny payloads over time) | Misses — each packet looks normal | Catches — payload size pattern across flow |
| Traffic to unusual internal endpoint | May or may not catch | Catches — whole flow behavior is unfamiliar |
| All traffic going one direction (upload only) | Misses | Catches — direction is a sequence-level feature |

A normal autoencoder asks: *"does this packet look weird?"*
FlowMAE asks: *"does this conversation look weird?"*

For data exfiltration, the conversation is almost always what's suspicious — not any single packet in isolation.

---

## PayloadMAE

An extension of FlowMAE that adds **payload content features** to each packet's feature vector. Requires decrypted PCAPs — if your traffic is TLS-encrypted, pre-decrypt it first:

```bash
tshark -r encrypted.pcap -o tls.keylog_file:keys.log -w decrypted.pcap
```

### Why payload features matter

FlowMAE sees *how* traffic flows (timing, size, direction). PayloadMAE also sees *what* is inside each packet. This closes a gap: an attacker who mimics normal flow metadata (correct timing, normal-looking packet sizes) but is still sending unusual byte patterns will evade FlowMAE but not PayloadMAE.

### Features per packet (14 total)

The original 8 metadata features plus 6 payload statistics:

| Feature | Description |
|---|---|
| `payload_entropy` | Shannon entropy of payload bytes (0–8 bits). High entropy = encrypted/compressed/random data |
| `byte_mean` | Mean byte value (0–255). Base64 clusters near 80; binary data spreads differently |
| `byte_std` | Std deviation of byte values. Low = repetitive/structured; high = random |
| `printable_ratio` | Fraction of bytes in printable ASCII range (0x20–0x7e). Low = binary blob |
| `high_byte_ratio` | Fraction of bytes > 127. High = non-ASCII / binary payload |
| `unique_byte_ratio` | Fraction of all 256 possible byte values present. Encrypted data uses nearly all 256 |

### What PayloadMAE catches that FlowMAE misses

| Pattern | FlowMAE | PayloadMAE |
|---|---|---|
| Exfil disguised as normal-sized, normal-timed packets | Misses — metadata looks clean | Catches — payload entropy/content is unusual |
| Base64-encoded data in HTTP bodies | Misses | Catches — byte mean and printable ratio shift |
| Binary blobs sent over plain HTTP | May miss | Catches — high_byte_ratio and entropy spike |
| Plaintext credential dumps | Misses | Catches — printable ratio near 1.0 in an unusual flow |
| Encrypted C2 over mimicked-normal flow timing | Misses | Catches — near-uniform byte distribution |

### Architecture

Identical to FlowMAE — same Transformer MAE — but the input/output dimension is 14 instead of 8.

```
PCAP → group by 5-tuple → 32-packet windows × 14 features
     → linear projection → 32-dim
     → positional encoding
     → 2× Transformer encoder blocks (4 heads, FF=64)
     → Dense(14) reconstruction
     → MSE loss on masked (40%) positions only
```

### Create a new model

```bash
python payload_create_model_script.py decrypted_benign.pcap my_payload_model
```

### Continue training

```bash
python payload_train_model_script.py my_payload_model more_benign_decrypted.pcap [--output-name new_name]
```

### Test / detect

```bash
python payload_test_model_script.py my_payload_model suspect_decrypted.pcap [--verbose] [--plot] [--save-results out.json]
```

### Test results

See `payload_results.md` for results of the model tested against clean and dirty decrypted PCAPs.

---

## FlowMAE vs PayloadMAE — when to use which

| Scenario | Recommended |
|---|---|
| Traffic is still encrypted (no TLS keys) | FlowMAE only |
| Traffic is decrypted / plaintext | Both — run in parallel |
| Attacker is mimicking normal timing/sizes | PayloadMAE catches it |
| Attacker is using unusual flow patterns | FlowMAE catches it |
| Maximum detection coverage | Run both, flag if either fires |

---

## Legacy Pipelines

The `legacy/` folder contains the original PCAP autoencoder and CSV autoencoder pipelines.
These are fully functional but have been superseded by FlowMAE for this project.
See `legacy/pcap_autoencoder_lib.py` and `legacy/csv_autoencoder_lib.py` if you need
per-packet scoring or want to reference the earlier architecture.
