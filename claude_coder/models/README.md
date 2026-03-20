# Autoencoder Models

Each model is a trained anomaly-detection autoencoder. All models in this directory share the same file structure:

| File | Contents |
|------|----------|
| `<name>_autoencoder.h5` | Trained Keras model weights and architecture |
| `<name>_scaler.pkl` | Fitted StandardScaler — must be used when transforming any input |
| `<name>_config.pkl` | Anomaly threshold, feature list, encoding dimension |

---

## Architecture (CSV-based models)

All `csv_*` models use the improved architecture from `csv_autoencoder_lib.py`:

- **Input → 32 → 16 → [bottleneck] → 16 → 32 → Output**
- Bottleneck (`encoding_dim`): 8
- Output activation: `linear` (inputs are StandardScaler output, unbounded)
- Dropout (0.2) on decoder side only
- Trained with `EarlyStopping(patience=5)` on validation loss
- Anomaly threshold: 99th percentile of validation-split reconstruction error

**Input features (10):**

| Feature | Description |
|---------|-------------|
| `inter_arrival_time` | Time delta between consecutive packets |
| `packet_length` | Total captured packet size |
| `ip_ttl` | IP time-to-live |
| `ip_flags` | IP flags field |
| `ip_len` | IP layer length |
| `tcp_dport` | TCP destination port |
| `tcp_dataofs` | TCP data offset (header length) |
| `tcp_flags` | TCP control flags (SYN, ACK, FIN, PSH, etc.) |
| `tcp_window` | TCP window size |
| `payload_len` | TCP payload size |

> `tcp_seq` and `tcp_ack` are intentionally excluded — they are
> essentially random values and add noise without improving detection.

---

## Models

### `clean_tcp_nossl`

- **Type:** CSV-based autoencoder (`csv_autoencoder_lib.py`)
- **Training data:** `clean_decrypted_tcp_features.csv`
- **What it learned:**
- **Recommended use:** Detecting anomalies in TCP-only traffic captures (no SSL/TLS). Best candidate for catching the keylogger's plain-HTTP-over-TCP exfiltration pattern since the training distribution is tight — only non-SSL TCP traffic (SSH, handshakes, ACKs).
- **Test with:**
  ```bash
  python csv_test_model_script.py clean_tcp_nossl <test_features.csv> --plot --verbose
  ```

---

### `clean_tcp_withssl`

- **Type:** CSV-based autoencoder (`csv_autoencoder_lib.py`)
- **Training data:** `clean_decrypted_tcp_withssl_features.csv`
- **What it learned:**
- **Recommended use:** Detecting anomalies in mixed TCP traffic that includes SSL/TLS. Broader training distribution means it may be less sensitive to the keylogger pattern specifically, but is more robust to environments with HTTPS traffic present.
- **Test with:**
  ```bash
  python csv_test_model_script.py clean_tcp_withssl <test_features.csv> --plot --verbose
  ```

---

## Legacy Models (PCAP-based)

The following models were created with the original `pcap_autoencoder_lib.py` pipeline.
They use a different feature set (includes `tcp_seq`, `tcp_ack`; excludes `inter_arrival_time`
and `payload_len`) and a `sigmoid` output activation. See `pcap_autoencoder_lib.py` for details.

### `firsttest`
- **Training data:**
- **Notes:**

### `decrypted_data1`
- **Training data:**
- **Notes:**

### `decrypted_tcp_withssl`
- **Training data:**
- **Notes:**

### `encrypted_data1`
- **Training data:**
- **Notes:**

---

## FlowMAE Models (PCAP-based, flow-sequence)

FlowMAE models group packets into flows by 5-tuple and run a Transformer
Masked Autoencoder over each flow's packet sequence. Anomaly scoring is
per-flow rather than per-packet, making it sensitive to temporal exfil
patterns (beaconing, slow-drip, directional asymmetry, DNS tunnelling).

**File structure:**

| File | Contents |
|------|----------|
| `<name>_flowmae.h5` | Trained Keras FlowMAE model |
| `<name>_flowmae_config.pkl` | Threshold, scaler, and hyperparameters |

**Architecture:**

- Packets grouped by 5-tuple `(ip_a:port_a) <-> (ip_b:port_b) [proto]`
- Flows split into non-overlapping 32-packet windows
- Each window: `(32 packets × 8 features)` → linear projection → 32-dim
- Positional encoding + 2× Transformer encoder blocks (4 heads, FF=64)
- Decoder: `Dense(8)` reconstruction per packet slot
- Training loss: MSE on masked (40%) positions only
- Anomaly score: avg masked-MSE across 5 independent mask samples per window
- Threshold: 99th percentile of per-window scores on training data

**Input features (8 per packet):**

| Feature | Description |
|---------|-------------|
| `inter_arrival_time` | Seconds since previous packet in this flow |
| `packet_length` | Total wire length in bytes |
| `ip_ttl` | IP time-to-live |
| `ip_flags` | IP flags (DF, MF) |
| `tcp_flags` | TCP control flags (0 for non-TCP) |
| `tcp_window` | TCP receive window (0 for non-TCP) |
| `payload_len` | Application payload bytes |
| `direction` | 0 = initiator→responder, 1 = responder→initiator |

---

### `flow_clean_tcp_withssl`

- **Type:** FlowMAE (`flow_mae_lib.py`)
- **Training PCAP:** `clean_decrypted_tcp_withssl.pcap`
- **Training data:** 728,039 packets → 4,041 flows → 24,566 flow windows
- **Epochs trained:** 30 (full — val_loss still improving at epoch 30)
- **Final val_loss:** 0.2543
- **Anomaly threshold:** 0.847419 (99th pct of training window scores)
- **What it learned:** Normal mixed TCP+SSL/TLS traffic patterns — typical
  connection timing, payload sizes, TCP flag sequences, and directional
  flow ratios seen in clean decrypted captures.
- **Recommended use:** Baseline for detecting exfiltration flows in
  environments with both plain TCP and SSL/TLS present. Flow-level scoring
  surfaces beaconing, slow-drip, and asymmetric upload patterns that
  per-packet models miss.
- **Test with:**
  ```bash
  python flow_test_model_script.py flow_clean_tcp_withssl <test.pcap> --verbose --plot
  ```

---

## Usage Reference

```bash
# ── CSV autoencoder ───────────────────────────────────────────────────────
# Create a new model from a CSV feature file
python csv_create_model_script.py <features.csv> <model_name>

# Continue training an existing model with more benign data
python csv_train_model_script.py <model_name> <more_features.csv>

# Test a model against a CSV feature file
python csv_test_model_script.py <model_name> <test_features.csv> [--plot] [--verbose] [--save-results out.json]

# Generate CSV feature files from pcaps
python /path/to/tcpO/extract_features.py

# ── FlowMAE (PCAP → flow sequences) ──────────────────────────────────────
# Create a new FlowMAE model directly from a PCAP
python flow_create_model_script.py <benign.pcap> <model_name> [--epochs 30] [--batch-size 32]

# Continue training a FlowMAE with additional benign PCAP data
python flow_train_model_script.py <model_name> <more_benign.pcap> [--output-name new_name]

# Test a FlowMAE against a PCAP — reports anomalous flows by 5-tuple
python flow_test_model_script.py <model_name> <test.pcap> [--verbose] [--plot] [--save-results out.json]
```
