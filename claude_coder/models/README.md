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

## Usage Reference

```bash
# Create a new model from a CSV feature file
python csv_create_model_script.py <features.csv> <model_name>

# Continue training an existing model with more benign data
python csv_train_model_script.py <model_name> <more_features.csv>

# Test a model against a CSV feature file
python csv_test_model_script.py <model_name> <test_features.csv> [--plot] [--verbose] [--save-results out.json]

# Generate CSV feature files from pcaps
python /path/to/tcpO/extract_features.py
```
