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

---

## PayloadMAE Models (PCAP-based, flow-sequence + payload content)

PayloadMAE extends FlowMAE by adding 6 payload byte statistics to each packet's
feature vector (14 features total instead of 8). Requires decrypted PCAPs.

**File structure:**

| File | Contents |
|------|----------|
| `<name>_payloadmae.weights.h5` | Trained Keras PayloadMAE weights |
| `<name>_payloadmae_config.pkl` | Threshold, scaler, and hyperparameters |

**Architecture:**

- Same Transformer MAE as FlowMAE
- Input/output dimension: 14 (8 metadata + 6 payload statistics)
- Packets grouped by 5-tuple, split into 32-packet windows
- Training: MSE on masked (40%) positions only
- Threshold: 99th percentile of per-window scores on training data

**Payload features (6 additional per packet):**

| Feature | Description |
|---------|-------------|
| `payload_entropy` | Shannon entropy (0–8 bits) of raw payload bytes |
| `byte_mean` | Mean byte value (0–255) |
| `byte_std` | Std deviation of byte values |
| `printable_ratio` | Fraction of bytes in printable ASCII range 0x20–0x7e |
| `high_byte_ratio` | Fraction of bytes > 127 |
| `unique_byte_ratio` | Fraction of all 256 byte values present in payload |

---

### `payload_clean_tcp_withssl`

- **Type:** PayloadMAE (`payload_mae_lib.py`)
- **Training PCAP:** `clean_decrypted_tcp_withssl.pcap`
- **Training data:** *(run `payload_create_model_script.py` to populate)*
- **Anomaly threshold:** *(set at training time — 99th pct of training windows)*
- **What it learned:** Normal payload byte patterns in mixed TCP+SSL/TLS decrypted
  traffic — typical entropy levels for web content, expected printable ratios for
  HTTP responses, byte distributions of normal application data.
- **Recommended use:** Companion to `flow_clean_tcp_withssl`. Run both models
  in parallel for maximum coverage. PayloadMAE catches attackers who successfully
  mimic normal flow timing/sizing but whose payload byte patterns remain unusual.
- **Test with:**
  ```bash
  python payload_test_model_script.py payload_clean_tcp_withssl <decrypted_test.pcap> --verbose --plot
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

# ── PayloadMAE (decrypted PCAP → flow sequences + payload content) ────────
# Pre-decrypt with tshark if needed:
#   tshark -r encrypted.pcap -o tls.keylog_file:keys.log -w decrypted.pcap

# Create a new PayloadMAE model from a decrypted benign PCAP
python payload_create_model_script.py <decrypted_benign.pcap> <model_name> [--epochs 30] [--batch-size 32]

# Continue training a PayloadMAE with additional decrypted benign data
python payload_train_model_script.py <model_name> <more_decrypted.pcap> [--output-name new_name]

# Test a PayloadMAE against a decrypted PCAP — reports anomalous flows by 5-tuple
python payload_test_model_script.py <model_name> <decrypted_test.pcap> [--verbose] [--plot] [--save-results out.json]
```
