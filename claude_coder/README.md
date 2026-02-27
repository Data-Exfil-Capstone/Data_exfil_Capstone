# PCAP Autoencoder - Network Anomaly Detection

A machine learning system that uses autoencoders to detect anomalous network traffic from PCAP files. Designed to identify data exfiltration attempts by learning normal traffic patterns and flagging deviations.

## How It Works

1. **Train** on PCAP captures of normal/benign network traffic
2. The autoencoder learns to reconstruct normal packet features with low error
3. **Test** against new traffic — packets that reconstruct poorly are flagged as anomalous
4. Traffic is classified as **SUSPICIOUS** if >10% of packets are anomalous

## Project Structure

```
claude_coder/
├── pcap_autoencoder_lib.py    # Core library (PCAPAutoencoder class)
├── create_model_script.py     # Create and train a new model
├── train_model_script.py      # Continue training an existing model
├── test_model_script.py       # Test traffic against a trained model
└── models/                    # Saved model files
    ├── *_autoencoder.h5       # Keras model weights
    ├── *_scaler.pkl           # Feature scaler
    └── *_config.pkl           # Model configuration & threshold
```

## Requirements

- Python 3
- TensorFlow / Keras
- Scapy
- scikit-learn
- NumPy
- Pandas
- Matplotlib

Install dependencies:

```bash
pip install tensorflow scapy scikit-learn numpy pandas matplotlib
```

## Usage

### Create a New Model

Train a new autoencoder on a PCAP file of normal traffic:

```bash
python create_model_script.py normal_traffic.pcap my_model
```

Options:

| Flag | Default | Description |
|------|---------|-------------|
| `--encoding-dim` | 16 | Bottleneck layer dimension |
| `--epochs` | 50 | Training iterations |
| `--batch-size` | 32 | Batch size |
| `--validation-split` | 0.2 | Fraction of data used for validation |

### Continue Training

Refine an existing model with additional normal traffic:

```bash
python train_model_script.py my_model more_traffic.pcap
```

Options:

| Flag | Default | Description |
|------|---------|-------------|
| `--epochs` | 10 | Additional training epochs |
| `--batch-size` | 32 | Batch size |
| `--validation-split` | 0.2 | Validation split |
| `--output-name` | (same) | Save as a new model instead of overwriting |

### Test / Detect Anomalies

Analyze a PCAP file for anomalous traffic:

```bash
python test_model_script.py my_model suspect_traffic.pcap
```

Options:

| Flag | Description |
|------|-------------|
| `--threshold` | Custom anomaly threshold (overrides learned value) |
| `--plot` | Display reconstruction error plot |
| `--save-plot FILE` | Save plot to a file |
| `--save-results FILE` | Export results as JSON |
| `--verbose` | Show details for each anomalous packet |

Exit codes: `0` = normal traffic, `1` = suspicious/malicious traffic.

## Features Extracted Per Packet

The system extracts 17+ features from each packet including:

- **IP layer** — version, header length, TOS, total length, flags, TTL, protocol
- **Transport layer** — source/destination ports, sequence/ack numbers, data offset, flags, window size
- **Protocol indicators** — TCP, UDP, ICMP flags
- **General** — raw packet length

## Detection Logic

- Individual packets are flagged if their reconstruction error exceeds the 95th percentile of training errors
- Overall traffic is classified as **SUSPICIOUS** when more than 10% of packets are anomalous
