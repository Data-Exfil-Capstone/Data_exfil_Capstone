"""
flow_mae_lib.py
Masked Autoencoder (MAE) over network flows grouped by 5-tuple.

Each packet in a flow contributes a feature vector. Flows are windowed
into fixed-length sequences. During training a random 40% of packet slots
are masked and the Transformer must reconstruct them — forcing it to learn
what a "normal" conversation between two endpoints looks like over time.

Anomaly score is per-flow MSE on masked positions averaged across several
independent mask samples. High score → the flow's packet sequence does not
resemble anything seen during benign training.
"""

import os
import pickle
import numpy as np
import pandas as pd
import tensorflow as tf
from tensorflow import keras
from tensorflow.keras import layers
from collections import defaultdict
import matplotlib.pyplot as plt

try:
    from scapy.all import rdpcap, IP, TCP, UDP, ICMP, Raw
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

MODELS_DIR = "models"

# Features extracted per packet within a flow
FLOW_FEATURES = [
    'inter_arrival_time',   # seconds since previous packet in this flow
    'packet_length',        # total wire length in bytes
    'ip_ttl',               # IP time-to-live
    'ip_flags',             # IP flags (DF, MF)
    'tcp_flags',            # TCP control flags (0 for non-TCP)
    'tcp_window',           # TCP receive window (0 for non-TCP)
    'payload_len',          # application payload bytes
    'direction',            # 0 = initiator→responder, 1 = responder→initiator
]
N_FEATURES = len(FLOW_FEATURES)


# ─────────────────────────────────────────────────────────────────────────────
# Keras building blocks
# ─────────────────────────────────────────────────────────────────────────────

class PositionalEncoding(layers.Layer):
    """Sinusoidal positional encoding added to the token sequence."""

    def __init__(self, seq_len, d_model, **kwargs):
        super().__init__(**kwargs)
        positions = np.arange(seq_len)[:, np.newaxis]
        dims      = np.arange(d_model)[np.newaxis, :]
        angles    = positions / np.power(10000, (2 * (dims // 2)) / d_model)
        angles[:, 0::2] = np.sin(angles[:, 0::2])
        angles[:, 1::2] = np.cos(angles[:, 1::2])
        # Shape: (1, seq_len, d_model) — broadcast over batch
        self._pe = tf.constant(angles[np.newaxis], dtype=tf.float32)

    def call(self, x):
        return x + self._pe

    def get_config(self):
        cfg = super().get_config()
        cfg.update({'pe': self._pe.numpy().tolist()})
        return cfg


class TransformerBlock(layers.Layer):
    """Single Transformer encoder block with pre-LN residual connections."""

    def __init__(self, d_model, num_heads, ff_dim, dropout=0.1, **kwargs):
        super().__init__(**kwargs)
        self.attn  = layers.MultiHeadAttention(
            num_heads=num_heads, key_dim=d_model // num_heads, dropout=dropout
        )
        self.ffn1  = layers.Dense(ff_dim, activation='gelu')
        self.ffn2  = layers.Dense(d_model)
        self.norm1 = layers.LayerNormalization(epsilon=1e-6)
        self.norm2 = layers.LayerNormalization(epsilon=1e-6)
        self.drop  = layers.Dropout(dropout)

    def call(self, x, training=False):
        attn_out = self.attn(x, x, training=training)
        x = self.norm1(x + self.drop(attn_out, training=training))
        ffn_out  = self.ffn2(self.ffn1(x))
        x = self.norm2(x + self.drop(ffn_out,  training=training))
        return x

    def get_config(self):
        cfg = super().get_config()
        cfg.update({
            'd_model':   self.ffn2.units,
            'num_heads': self.attn._num_heads,
            'ff_dim':    self.ffn1.units,
        })
        return cfg


# ─────────────────────────────────────────────────────────────────────────────
# Main class
# ─────────────────────────────────────────────────────────────────────────────

class FlowMAE:
    """
    Masked Autoencoder over 5-tuple network flows from PCAP files.

    Hyperparameters
    ───────────────
    MAX_FLOW_LEN : packets per flow window (longer flows are split)
    MIN_FLOW_LEN : minimum packets to keep a flow (shorter ones are discarded)
    MASK_RATIO   : fraction of packet slots masked per training step
    D_MODEL      : Transformer hidden dimension
    NUM_HEADS    : attention heads
    FF_DIM       : feed-forward inner dimension
    NUM_LAYERS   : number of Transformer blocks
    """

    MAX_FLOW_LEN = 32
    MIN_FLOW_LEN = 4
    MASK_RATIO   = 0.40
    D_MODEL      = 32
    NUM_HEADS    = 4
    FF_DIM       = 64
    NUM_LAYERS   = 2

    def __init__(self):
        self.model     = None
        self.scaler    = None
        self.threshold = None
        self._opt      = None   # optimizer kept alive across continue_training calls

    # ── PCAP → flow feature extraction ───────────────────────────────────────

    def extract_flows(self, pcap_file: str) -> dict:
        """
        Read a PCAP and return a dict mapping 5-tuple → list-of-feature-dicts.

        5-tuple key: ((ip_a, port_a), (ip_b, port_b), proto)
        where (ip_a, port_a) ≤ (ip_b, port_b) so A→B and B→A share the same key.
        """
        if not SCAPY_AVAILABLE:
            raise RuntimeError("scapy is required: pip install scapy")

        print(f"Reading {pcap_file} ...")
        packets = rdpcap(pcap_file)
        print(f"  {len(packets)} packets loaded.")

        flows    = defaultdict(list)
        prev_ts  = {}

        for pkt in packets:
            if IP not in pkt:
                continue

            proto = pkt[IP].proto

            if TCP in pkt:
                sport, dport = pkt[TCP].sport, pkt[TCP].dport
                tcp_flags    = int(pkt[TCP].flags)
                tcp_window   = pkt[TCP].window
            elif UDP in pkt:
                sport, dport = pkt[UDP].sport, pkt[UDP].dport
                tcp_flags    = 0
                tcp_window   = 0
            else:
                sport = dport = 0
                tcp_flags     = 0
                tcp_window    = 0

            ep1 = (pkt[IP].src, sport)
            ep2 = (pkt[IP].dst, dport)

            # Canonical key: sort endpoints so both directions share one entry
            if ep1 <= ep2:
                key       = (ep1, ep2, proto)
                direction = 0
            else:
                key       = (ep2, ep1, proto)
                direction = 1

            ts  = float(pkt.time)
            iat = ts - prev_ts.get(key, ts)
            prev_ts[key] = ts

            payload_len = len(pkt[Raw].load) if Raw in pkt else 0

            flows[key].append({
                'inter_arrival_time': float(iat),
                'packet_length':      float(len(pkt)),
                'ip_ttl':             float(pkt[IP].ttl),
                'ip_flags':           float(int(pkt[IP].flags)),
                'tcp_flags':          float(tcp_flags),
                'tcp_window':         float(tcp_window),
                'payload_len':        float(payload_len),
                'direction':          float(direction),
            })

        # Drop flows too short to be meaningful
        flows = {k: v for k, v in flows.items() if len(v) >= self.MIN_FLOW_LEN}
        print(f"  {len(flows)} flows after filtering (min_len={self.MIN_FLOW_LEN}).")
        return flows

    def _flows_to_windows(self, flows: dict):
        """
        Chop each flow into non-overlapping windows of MAX_FLOW_LEN packets.
        Zero-pad the final window if the flow doesn't divide evenly.

        Returns:
            windows   : np.ndarray (N_windows, MAX_FLOW_LEN, N_FEATURES) float32
            window_keys: list of 5-tuple keys, one per window (for reporting)
        """
        L       = self.MAX_FLOW_LEN
        windows = []
        keys    = []

        for key, pkts in flows.items():
            arr = np.array([[p[f] for f in FLOW_FEATURES] for p in pkts],
                           dtype=np.float32)   # (n_pkts, N_FEATURES)

            # Slide through the flow in non-overlapping windows
            for start in range(0, len(arr), L):
                chunk = arr[start: start + L]
                if len(chunk) < self.MIN_FLOW_LEN:
                    break                      # last tiny remnant — skip
                # Zero-pad if shorter than L
                if len(chunk) < L:
                    pad   = np.zeros((L - len(chunk), N_FEATURES), dtype=np.float32)
                    chunk = np.vstack([chunk, pad])
                windows.append(chunk)
                keys.append(key)

        if not windows:
            raise ValueError("No valid flow windows extracted from PCAP.")

        return np.stack(windows, axis=0), keys  # (N, L, F)

    # ── Masking ───────────────────────────────────────────────────────────────

    @staticmethod
    def _mask(X: np.ndarray, ratio: float):
        """
        Zero-mask `ratio` fraction of packet slots per window.
        Returns (X_masked, mask) where mask[i, j]=True means slot j was masked.
        """
        B, L, _ = X.shape
        mask     = np.random.rand(B, L) < ratio          # (B, L) bool
        X_m      = X.copy()
        X_m[mask] = 0.0
        return X_m.astype(np.float32), mask

    # ── Model ─────────────────────────────────────────────────────────────────

    def build_model(self):
        L = self.MAX_FLOW_LEN
        d = self.D_MODEL

        inp = layers.Input(shape=(L, N_FEATURES), name='flow_input')

        # Project feature vector to d_model
        x = layers.Dense(d, name='feat_proj')(inp)

        # Positional encoding
        x = PositionalEncoding(L, d, name='pos_enc')(x)

        # Transformer encoder stack
        for i in range(self.NUM_LAYERS):
            x = TransformerBlock(d, self.NUM_HEADS, self.FF_DIM,
                                 name=f'transformer_{i}')(x)

        # Reconstruct packet feature vectors
        out = layers.Dense(N_FEATURES, name='reconstruction')(x)

        self.model = keras.Model(inp, out, name='FlowMAE')
        print(self.model.summary())

    # ── Training loop ─────────────────────────────────────────────────────────

    def _make_optimizer(self):
        return keras.optimizers.Adam(learning_rate=1e-3)

    @tf.function
    def _train_step(self, x_masked, x_true, mask, optimizer):
        with tf.GradientTape() as tape:
            recon   = self.model(x_masked, training=True)          # (B, L, F)
            sq_err  = tf.square(x_true - recon)                    # (B, L, F)
            pkt_mse = tf.reduce_mean(sq_err, axis=-1)              # (B, L)
            mask_f  = tf.cast(mask, tf.float32)
            loss    = (tf.reduce_sum(pkt_mse * mask_f)
                       / (tf.reduce_sum(mask_f) + 1e-8))
        grads = tape.gradient(loss, self.model.trainable_variables)
        optimizer.apply_gradients(zip(grads, self.model.trainable_variables))
        return loss

    def _run_epochs(self, X: np.ndarray, epochs: int, batch_size: int,
                    val_fraction: float = 0.1):
        """
        Core training loop shared by train() and continue_training().
        Returns final validation loss.
        """
        # Train / val split
        n_val  = max(1, int(len(X) * val_fraction))
        X_val  = X[-n_val:]
        X_tr   = X[:-n_val]

        dataset = (tf.data.Dataset
                   .from_tensor_slices(X_tr)
                   .shuffle(5000)
                   .batch(batch_size))

        best_val  = float('inf')
        patience  = 5
        no_improve = 0

        for epoch in range(epochs):
            train_losses = []
            for batch in dataset:
                b_np          = batch.numpy()
                x_m, mask_np  = self._mask(b_np, self.MASK_RATIO)
                loss = self._train_step(
                    tf.constant(x_m),
                    tf.constant(b_np),
                    tf.constant(mask_np),
                    self._opt,
                )
                train_losses.append(float(loss))

            # Validation loss (no gradient)
            x_m_val, mask_val = self._mask(X_val, self.MASK_RATIO)
            recon_val = self.model(x_m_val, training=False).numpy()
            sq_err    = (X_val - recon_val) ** 2
            pkt_mse   = sq_err.mean(axis=-1)
            mask_f    = mask_val.astype(np.float32)
            val_loss  = float(
                (pkt_mse * mask_f).sum() / (mask_f.sum() + 1e-8)
            )

            print(f"  Epoch {epoch+1}/{epochs}  "
                  f"train_loss={np.mean(train_losses):.5f}  "
                  f"val_loss={val_loss:.5f}")

            if val_loss < best_val - 1e-6:
                best_val   = val_loss
                no_improve = 0
                self.model.save_weights('/tmp/flowmae_best_weights.weights.h5')
            else:
                no_improve += 1
                if no_improve >= patience:
                    print(f"  Early stopping at epoch {epoch+1}.")
                    break

        self.model.load_weights('/tmp/flowmae_best_weights.weights.h5')
        return best_val

    # ── Public API ────────────────────────────────────────────────────────────

    def train(self, pcap_file: str, epochs: int = 30, batch_size: int = 32):
        """
        Train from scratch on benign PCAP traffic.
        Fits scaler, builds model, trains, and sets anomaly threshold.
        """
        from sklearn.preprocessing import StandardScaler

        flows      = self.extract_flows(pcap_file)
        X_raw, _   = self._flows_to_windows(flows)         # (N, L, F)
        N, L, F    = X_raw.shape
        print(f"\n{N} flow windows  |  window_len={L}  |  features={F}")

        self.scaler = StandardScaler()
        X = self.scaler.fit_transform(
            X_raw.reshape(-1, F)
        ).reshape(N, L, F).astype(np.float32)

        self.build_model()
        self._opt = self._make_optimizer()

        print(f"\nTraining ({epochs} epochs, batch={batch_size}) ...")
        self._run_epochs(X, epochs, batch_size)

        # Threshold: 99th percentile of per-window anomaly scores on training data
        scores         = self._score_windows(X)
        self.threshold = float(np.percentile(scores, 99))
        print(f"\nAnomaly threshold (99th pct on training data): {self.threshold:.6f}")

    def continue_training(self, pcap_file: str, epochs: int = 10,
                          batch_size: int = 32):
        """
        Continue training an already-loaded model with additional benign PCAP data.
        The scaler is NOT re-fitted — new data is transformed with the existing scaler.
        Threshold is updated to reflect both old and new data distributions.
        """
        if self.model is None:
            raise ValueError("No model loaded. Call train() or load_model() first.")

        flows      = self.extract_flows(pcap_file)
        X_raw, _   = self._flows_to_windows(flows)
        N, L, F    = X_raw.shape
        print(f"\n{N} flow windows from new data.")

        X = self.scaler.transform(
            X_raw.reshape(-1, F)
        ).reshape(N, L, F).astype(np.float32)

        if self._opt is None:
            self._opt = self._make_optimizer()

        print(f"\nContinuing training ({epochs} epochs, batch={batch_size}) ...")
        self._run_epochs(X, epochs, batch_size)

        scores         = self._score_windows(X)
        self.threshold = float(np.percentile(scores, 99))
        print(f"\nUpdated threshold: {self.threshold:.6f}")

    # ── Scoring / detection ───────────────────────────────────────────────────

    def _score_windows(self, X: np.ndarray, n_masks: int = 5,
                       batch_size: int = 512) -> np.ndarray:
        """
        Per-window anomaly score: average MSE on masked positions across n_masks trials.
        Processes in batches to avoid GPU OOM on large PCAPs.
        Shape: (N_windows,)
        """
        total = np.zeros(len(X), dtype=np.float64)
        for _ in range(n_masks):
            batch_scores = []
            for start in range(0, len(X), batch_size):
                Xb        = X[start: start + batch_size]
                x_m, mask = self._mask(Xb, self.MASK_RATIO)
                recon     = self.model(x_m, training=False).numpy()    # (B, L, F)
                pkt_mse   = np.mean((Xb - recon) ** 2, axis=-1)       # (B, L)
                mask_f    = mask.astype(np.float64)
                scores    = (pkt_mse * mask_f).sum(axis=1) / (mask_f.sum(axis=1) + 1e-8)
                batch_scores.append(scores)
            total += np.concatenate(batch_scores)
        return (total / n_masks).astype(np.float32)

    def detect_anomalies(self, pcap_file: str, threshold: float = None) -> dict:
        """
        Detect anomalous flows in a PCAP file.

        Returns a dict with per-flow scores, flagged flow keys, and an
        overall malicious classification.
        """
        if self.model is None:
            raise ValueError("No model loaded. Call train() or load_model() first.")

        threshold  = threshold if threshold is not None else self.threshold

        flows      = self.extract_flows(pcap_file)
        X_raw, wkeys = self._flows_to_windows(flows)
        N, L, F    = X_raw.shape

        X = self.scaler.transform(
            X_raw.reshape(-1, F)
        ).reshape(N, L, F).astype(np.float32)

        print(f"\nScoring {N} flow windows ...")
        scores    = self._score_windows(X)
        anomalies = scores > threshold

        # Map window-level flags back to flow keys
        flagged_flows = {}
        for i, (key, score, flag) in enumerate(zip(wkeys, scores, anomalies)):
            key_str = _key_to_str(key)
            if key_str not in flagged_flows or flagged_flows[key_str]['score'] < score:
                flagged_flows[key_str] = {
                    'score':     float(score),
                    'anomalous': bool(flag),
                }

        n_flagged   = int(anomalies.sum())
        n_anom_flows = sum(1 for v in flagged_flows.values() if v['anomalous'])

        results = {
            'total_windows':       N,
            'total_flows':         len(flows),
            'anomalous_windows':   n_flagged,
            'anomalous_flows':     n_anom_flows,
            'anomaly_window_pct':  float(n_flagged / N * 100),
            'anomaly_flow_pct':    float(n_anom_flows / len(flows) * 100),
            'window_scores':       scores.tolist(),
            'flow_details':        flagged_flows,
            'threshold':           float(threshold),
            # Flag as malicious if >5% of flows look anomalous
            'is_malicious':        n_anom_flows / len(flows) > 0.05,
        }

        print(f"\nResults:")
        print(f"  Total flows analysed:   {results['total_flows']}")
        print(f"  Total windows scored:   {results['total_windows']}")
        print(f"  Anomalous windows:      {results['anomalous_windows']} "
              f"({results['anomaly_window_pct']:.1f}%)")
        print(f"  Anomalous flows:        {results['anomalous_flows']} "
              f"({results['anomaly_flow_pct']:.1f}%)")
        print(f"  Classification:         "
              f"{'SUSPICIOUS/MALICIOUS' if results['is_malicious'] else 'NORMAL'}")

        return results

    # ── Visualisation ─────────────────────────────────────────────────────────

    def plot_flow_scores(self, results: dict, save_path: str = None):
        """
        Bar chart of per-window anomaly scores with the threshold marked.
        Anomalous windows are highlighted in red.
        """
        scores    = np.array(results['window_scores'])
        threshold = results['threshold']
        colors    = ['#d62728' if s > threshold else '#1f77b4' for s in scores]

        plt.figure(figsize=(14, 5))
        plt.bar(range(len(scores)), scores, color=colors,
                alpha=0.8, width=1.0, label='Window score')
        plt.axhline(y=threshold, color='red', linestyle='--', linewidth=1.5,
                    label=f'Threshold ({threshold:.4f})')
        plt.xlabel('Flow window index')
        plt.ylabel('Anomaly score (masked MSE)')
        plt.title('Flow-level Anomaly Scores')
        plt.legend()
        plt.grid(True, axis='y', alpha=0.3)
        plt.tight_layout()

        if save_path:
            plt.savefig(save_path, dpi=300, bbox_inches='tight')
            print(f"Plot saved to {save_path}")
        plt.show()

    # ── Persistence ───────────────────────────────────────────────────────────

    def save_model(self, name: str):
        """
        Save weights and config separately so loading never depends on
        Keras being able to deserialize the custom layer classes.
        """
        os.makedirs(MODELS_DIR, exist_ok=True)
        prefix = os.path.join(MODELS_DIR, name)
        self.model.save_weights(f"{prefix}_flowmae.weights.h5")
        with open(f"{prefix}_flowmae_config.pkl", 'wb') as f:
            pickle.dump({
                'threshold':    self.threshold,
                'scaler':       self.scaler,
                'MAX_FLOW_LEN': self.MAX_FLOW_LEN,
                'MIN_FLOW_LEN': self.MIN_FLOW_LEN,
                'MASK_RATIO':   self.MASK_RATIO,
                'D_MODEL':      self.D_MODEL,
                'NUM_HEADS':    self.NUM_HEADS,
                'FF_DIM':       self.FF_DIM,
                'NUM_LAYERS':   self.NUM_LAYERS,
            }, f)
        print(f"Model saved: {MODELS_DIR}/{name}")

    def load_model(self, name: str):
        """
        Rebuild the architecture from saved hyperparameters, then load weights.
        This avoids any Keras custom-layer serialization issues.
        """
        prefix = os.path.join(MODELS_DIR, name)
        with open(f"{prefix}_flowmae_config.pkl", 'rb') as f:
            cfg = pickle.load(f)
        self.threshold    = cfg['threshold']
        self.scaler       = cfg['scaler']
        self.MAX_FLOW_LEN = cfg.get('MAX_FLOW_LEN', self.MAX_FLOW_LEN)
        self.MIN_FLOW_LEN = cfg.get('MIN_FLOW_LEN', self.MIN_FLOW_LEN)
        self.MASK_RATIO   = cfg.get('MASK_RATIO',   self.MASK_RATIO)
        self.D_MODEL      = cfg.get('D_MODEL',      self.D_MODEL)
        self.NUM_HEADS    = cfg.get('NUM_HEADS',     self.NUM_HEADS)
        self.FF_DIM       = cfg.get('FF_DIM',        self.FF_DIM)
        self.NUM_LAYERS   = cfg.get('NUM_LAYERS',    self.NUM_LAYERS)
        self.build_model()
        self.model.load_weights(f"{prefix}_flowmae.weights.h5")
        print(f"Model loaded: {MODELS_DIR}/{name}")
        print(f"  Threshold: {self.threshold:.6f}")


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _key_to_str(key) -> str:
    """Convert a 5-tuple flow key to a readable string."""
    (ip_a, port_a), (ip_b, port_b), proto = key
    proto_name = {6: 'TCP', 17: 'UDP', 1: 'ICMP'}.get(proto, str(proto))
    return f"{ip_a}:{port_a} <-> {ip_b}:{port_b} [{proto_name}]"
