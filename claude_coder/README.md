# Network Anomaly Detection — Autoencoder Suite

A machine learning system for detecting anomalous network traffic and data exfiltration attempts. Three separate pipelines are available depending on your input data and detection needs.

| Pipeline | Input | Anomaly unit | Status |
|---|---|---|---|
| **FlowMAE** | `.pcap` | Per flow | **Active** |
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

## Legacy Pipelines

The `legacy/` folder contains the original PCAP autoencoder and CSV autoencoder pipelines.
These are fully functional but have been superseded by FlowMAE for this project.
See `legacy/pcap_autoencoder_lib.py` and `legacy/csv_autoencoder_lib.py` if you need
per-packet scoring or want to reference the earlier architecture.
