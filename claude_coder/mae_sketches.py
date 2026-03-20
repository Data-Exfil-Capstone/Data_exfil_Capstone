"""
mae_sketches.py
Architectural sketches for two MAE approaches on raw PCAP data.

  1. ByteMAE  — Masked Autoencoder over raw payload bytes (per packet)
  2. FlowMAE  — Masked Autoencoder over packet sequences grouped by 5-tuple

Neither is wired to PCAP I/O yet — the feature extraction stubs show
what you would plug in. The model architectures are complete and trainable.
"""

import numpy as np
import tensorflow as tf
from tensorflow import keras
from tensorflow.keras import layers
from collections import defaultdict
import pickle, os

MODELS_DIR = "models"

# ─────────────────────────────────────────────────────────────────────────────
# Shared building blocks
# ─────────────────────────────────────────────────────────────────────────────

def positional_encoding(seq_len, d_model):
    """Standard sinusoidal positional encoding — same as the original Transformer."""
    positions = np.arange(seq_len)[:, np.newaxis]          # (seq_len, 1)
    dims      = np.arange(d_model)[np.newaxis, :]           # (1, d_model)
    angles    = positions / np.power(10000, (2 * (dims // 2)) / d_model)
    angles[:, 0::2] = np.sin(angles[:, 0::2])
    angles[:, 1::2] = np.cos(angles[:, 1::2])
    return tf.cast(angles[np.newaxis, :, :], tf.float32)    # (1, seq_len, d_model)


def transformer_encoder_block(d_model, num_heads, ff_dim, dropout=0.1):
    """Single Transformer encoder block returned as a Keras layer."""
    return keras.Sequential([
        layers.MultiHeadAttention(num_heads=num_heads, key_dim=d_model // num_heads),
        layers.Dropout(dropout),
        layers.LayerNormalization(epsilon=1e-6),
        layers.Dense(ff_dim, activation='gelu'),
        layers.Dense(d_model),
        layers.Dropout(dropout),
        layers.LayerNormalization(epsilon=1e-6),
    ])


# ─────────────────────────────────────────────────────────────────────────────
# 1. ByteMAE — masked autoencoder over raw payload bytes (per packet)
# ─────────────────────────────────────────────────────────────────────────────

class ByteMAE:
    """
    Treats each packet payload as a sequence of raw bytes (0-255).

    Architecture
    ─────────────
    Input  : (batch, MAX_PAYLOAD) integer byte values, zero-padded
    Embed  : byte embedding (256 vocab → d_model dims) + positional encoding
    Mask   : randomly zero-out MASK_RATIO fraction of positions at training time
    Encoder: stack of Transformer encoder blocks on ALL positions
             (masking is done by replacing tokens with a learned [MASK] vector,
              not by dropping positions — keeps sequence length fixed)
    Decoder: linear projection back to 256-class softmax per position
    Loss   : cross-entropy on MASKED positions only (like original MAE paper)

    Anomaly score
    ─────────────
    At inference, mask each position in turn (or use a fixed random mask set)
    and average the cross-entropy loss across all positions.
    High score → the model cannot predict what "should" be at those positions
                → the payload looks unlike anything it was trained on.
    """

    MAX_PAYLOAD = 256      # bytes per packet; truncate longer, zero-pad shorter
    MASK_RATIO  = 0.75     # fraction of byte positions masked during training
    D_MODEL     = 64       # embedding dimension
    NUM_HEADS   = 4
    FF_DIM      = 128
    NUM_LAYERS  = 3
    VOCAB_SIZE  = 257      # 0-255 bytes + 256 as the [MASK] token id

    def __init__(self):
        self.model     = None
        self.threshold = None

    # ── Feature extraction stub ───────────────────────────────────────────────

    @staticmethod
    def extract_payload(packet) -> np.ndarray:
        """
        STUB — plug in your scapy packet here.

        from scapy.all import Raw
        raw = bytes(packet[Raw].load) if Raw in packet else b''
        arr = np.frombuffer(raw[:ByteMAE.MAX_PAYLOAD], dtype=np.uint8)
        # zero-pad to MAX_PAYLOAD
        padded = np.zeros(ByteMAE.MAX_PAYLOAD, dtype=np.int32)
        padded[:len(arr)] = arr
        return padded
        """
        raise NotImplementedError("Wire up scapy payload extraction here.")

    @staticmethod
    def load_pcap_payloads(pcap_file) -> np.ndarray:
        """
        Returns array of shape (N_packets, MAX_PAYLOAD) with integer byte values.

        STUB:
        from scapy.all import rdpcap
        packets = rdpcap(pcap_file)
        return np.stack([ByteMAE.extract_payload(p) for p in packets])
        """
        raise NotImplementedError("Wire up PCAP loading here.")

    # ── Masking helper ────────────────────────────────────────────────────────

    @staticmethod
    def _apply_mask(X_int, mask_ratio):
        """
        Replace mask_ratio fraction of positions with MASK token id (256).
        Returns (masked_X, mask_bool) where mask_bool=True means 'was masked'.
        """
        B, L         = X_int.shape
        mask         = np.random.rand(B, L) < mask_ratio
        X_masked     = X_int.copy()
        X_masked[mask] = 256                               # [MASK] token
        return X_masked.astype(np.int32), mask

    # ── Model ─────────────────────────────────────────────────────────────────

    def build_model(self):
        seq_len = self.MAX_PAYLOAD
        d       = self.D_MODEL

        inp = layers.Input(shape=(seq_len,), dtype='int32', name='byte_input')

        # Byte embedding + positional encoding
        x = layers.Embedding(self.VOCAB_SIZE, d, name='byte_embed')(inp)
        x = x + positional_encoding(seq_len, d)            # broadcast add

        # Transformer encoder stack
        for i in range(self.NUM_LAYERS):
            attn_out = layers.MultiHeadAttention(
                num_heads=self.NUM_HEADS, key_dim=d // self.NUM_HEADS,
                name=f'attn_{i}'
            )(x, x)
            x = layers.LayerNormalization(epsilon=1e-6)(x + attn_out)
            ff_out = layers.Dense(self.FF_DIM, activation='gelu')(x)
            ff_out = layers.Dense(d)(ff_out)
            x = layers.LayerNormalization(epsilon=1e-6)(x + ff_out)

        # Decoder: project to byte vocabulary (256 classes, not 257 — we never predict [MASK])
        logits = layers.Dense(256, name='byte_logits')(x)  # (B, seq_len, 256)

        self.model = keras.Model(inp, logits, name='ByteMAE')
        # Loss is computed manually in train() so we can mask it
        self.model.compile(optimizer=keras.optimizers.Adam(1e-3))
        self.model.summary()

    # ── Training ──────────────────────────────────────────────────────────────

    def train(self, pcap_file, epochs=30, batch_size=64):
        X = self.load_pcap_payloads(pcap_file)             # (N, MAX_PAYLOAD)
        self.build_model()

        optimizer = keras.optimizers.Adam(1e-3)
        ce_loss   = keras.losses.SparseCategoricalCrossentropy(
            from_logits=True, reduction='none'
        )

        @tf.function
        def train_step(x_masked, x_true, mask):
            with tf.GradientTape() as tape:
                logits     = self.model(x_masked, training=True)  # (B, L, 256)
                token_loss = ce_loss(x_true, logits)              # (B, L)
                # Only backprop on masked positions
                mask_f     = tf.cast(mask, tf.float32)
                loss       = tf.reduce_sum(token_loss * mask_f) / (tf.reduce_sum(mask_f) + 1e-8)
            grads = tape.gradient(loss, self.model.trainable_variables)
            optimizer.apply_gradients(zip(grads, self.model.trainable_variables))
            return loss

        dataset = tf.data.Dataset.from_tensor_slices(X).shuffle(10000).batch(batch_size)

        for epoch in range(epochs):
            epoch_loss = []
            for batch in dataset:
                batch_np        = batch.numpy()
                masked, mask_np = self._apply_mask(batch_np, self.MASK_RATIO)
                loss = train_step(
                    tf.constant(masked),
                    tf.constant(batch_np),
                    tf.constant(mask_np)
                )
                epoch_loss.append(float(loss))
            print(f"Epoch {epoch+1}/{epochs}  loss={np.mean(epoch_loss):.4f}")

        # Threshold: 99th percentile anomaly score on training data
        scores = self._score_batch(X)
        self.threshold = float(np.percentile(scores, 99))
        print(f"Threshold set to {self.threshold:.4f}")

    # ── Inference ─────────────────────────────────────────────────────────────

    def _score_batch(self, X_int, n_masks=5):
        """
        Average cross-entropy over n_masks independent random masks.
        Higher = harder to reconstruct = more anomalous.
        """
        ce_loss = keras.losses.SparseCategoricalCrossentropy(
            from_logits=True, reduction='none'
        )
        total = np.zeros(len(X_int))
        for _ in range(n_masks):
            masked, mask = self._apply_mask(X_int, self.MASK_RATIO)
            logits       = self.model(masked, training=False).numpy()   # (B, L, 256)
            per_token    = ce_loss(X_int, logits).numpy()               # (B, L)
            mask_f       = mask.astype(np.float32)
            scores       = (per_token * mask_f).sum(axis=1) / (mask_f.sum(axis=1) + 1e-8)
            total       += scores
        return total / n_masks

    def detect_anomalies(self, pcap_file, threshold=None):
        X         = self.load_pcap_payloads(pcap_file)
        threshold = threshold or self.threshold
        scores    = self._score_batch(X)
        anomalies = scores > threshold

        results = {
            'total_packets':      len(X),
            'anomalous_packets':  int(anomalies.sum()),
            'anomaly_percentage': float(anomalies.mean() * 100),
            'anomaly_scores':     scores.tolist(),
            'threshold':          threshold,
            'is_malicious':       float(anomalies.mean()) > 0.1,
        }
        print(f"Anomalous: {results['anomalous_packets']}/{results['total_packets']} "
              f"({results['anomaly_percentage']:.2f}%)")
        return results

    def save_model(self, name):
        os.makedirs(MODELS_DIR, exist_ok=True)
        self.model.save(os.path.join(MODELS_DIR, f"{name}_bytemae.h5"))
        with open(os.path.join(MODELS_DIR, f"{name}_bytemae_config.pkl"), 'wb') as f:
            pickle.dump({'threshold': self.threshold}, f)

    def load_model(self, name):
        self.model = keras.models.load_model(
            os.path.join(MODELS_DIR, f"{name}_bytemae.h5"), compile=False
        )
        with open(os.path.join(MODELS_DIR, f"{name}_bytemae_config.pkl"), 'rb') as f:
            self.threshold = pickle.load(f)['threshold']


# ─────────────────────────────────────────────────────────────────────────────
# 2. FlowMAE — masked autoencoder over packet sequences grouped by 5-tuple
# ─────────────────────────────────────────────────────────────────────────────

# Features extracted per packet inside a flow
FLOW_FEATURES = [
    'inter_arrival_time',   # seconds since previous packet in flow
    'packet_length',        # total wire length
    'ip_ttl',
    'ip_flags',
    'tcp_flags',            # 0 if UDP/ICMP
    'tcp_window',
    'payload_len',          # bytes of application payload
    'direction',            # 0 = client→server, 1 = server→client
]
N_FLOW_FEATURES = len(FLOW_FEATURES)


class FlowMAE:
    """
    Groups packets into flows by 5-tuple, then runs a Transformer MAE
    over the sequence of packets within each flow.

    Architecture
    ─────────────
    Input  : (batch, MAX_FLOW_LEN, N_FLOW_FEATURES) float32 feature vectors
             Flows shorter than MAX_FLOW_LEN are zero-padded.
    Embed  : linear projection of feature vector → d_model + positional encoding
    Mask   : replace MASK_RATIO fraction of packet slots with learned [MASK] vector
    Encoder: Transformer encoder over all slots (masked + unmasked)
    Decoder: MLP per slot → reconstruct N_FLOW_FEATURES
    Loss   : MSE on masked slots only

    Why this catches exfil
    ──────────────────────
    - DNS tunnelling:  unusual inter-arrival timing + large query payload_len
    - HTTP exfil:      abnormal payload ratios (all upload, no download)
    - Beaconing:       hyper-regular inter_arrival_time across the flow
    - Slow drip:       flow length much longer than normal with tiny payloads

    Anomaly score
    ─────────────
    Per-flow MSE on masked positions — one score per flow, not per packet.
    Aggregate to session-level by taking the max over all flows in a session.
    """

    MAX_FLOW_LEN = 64      # packets per flow window; truncate longer flows
    MASK_RATIO   = 0.40    # lower than ByteMAE — fewer positions in a flow
    D_MODEL      = 32
    NUM_HEADS    = 4
    FF_DIM       = 64
    NUM_LAYERS   = 2

    def __init__(self):
        self.model     = None
        self.scaler    = None          # sklearn StandardScaler fitted per-feature
        self.threshold = None
        self._mask_vec = None          # learned [MASK] embedding, set after build

    # ── Feature extraction stub ───────────────────────────────────────────────

    @staticmethod
    def extract_flows(pcap_file) -> dict:
        """
        STUB — returns dict mapping 5-tuple → list of per-packet feature dicts.

        EXAMPLE with scapy:
        ───────────────────
        from scapy.all import rdpcap, IP, TCP, UDP, Raw

        packets  = rdpcap(pcap_file)
        flows    = defaultdict(list)
        prev_ts  = {}

        for pkt in packets:
            if IP not in pkt:
                continue
            proto = pkt[IP].proto
            sport = pkt[TCP].sport if TCP in pkt else (pkt[UDP].sport if UDP in pkt else 0)
            dport = pkt[TCP].dport if TCP in pkt else (pkt[UDP].dport if UDP in pkt else 0)

            # Canonical 5-tuple (sort src/dst so A→B and B→A are same flow)
            ep1   = (pkt[IP].src, sport)
            ep2   = (pkt[IP].dst, dport)
            key   = (min(ep1, ep2), max(ep1, ep2), proto)
            direc = 0 if ep1 <= ep2 else 1

            iat   = pkt.time - prev_ts.get(key, pkt.time)
            prev_ts[key] = pkt.time

            payload = bytes(pkt[Raw].load) if Raw in pkt else b''
            flows[key].append({
                'inter_arrival_time': float(iat),
                'packet_length':      len(pkt),
                'ip_ttl':             pkt[IP].ttl,
                'ip_flags':           int(pkt[IP].flags),
                'tcp_flags':          int(pkt[TCP].flags) if TCP in pkt else 0,
                'tcp_window':         pkt[TCP].window    if TCP in pkt else 0,
                'payload_len':        len(payload),
                'direction':          direc,
            })
        return flows
        """
        raise NotImplementedError("Wire up scapy flow extraction here.")

    @staticmethod
    def flows_to_array(flows: dict, max_len: int) -> np.ndarray:
        """
        Convert flow dict → (N_flows, max_len, N_FLOW_FEATURES) float32 array.
        Truncates long flows, zero-pads short ones.
        """
        out = []
        for pkts in flows.values():
            seq = [[p[f] for f in FLOW_FEATURES] for p in pkts[:max_len]]
            # zero-pad
            while len(seq) < max_len:
                seq.append([0.0] * N_FLOW_FEATURES)
            out.append(seq)
        return np.array(out, dtype=np.float32)   # (N, max_len, N_features)

    # ── Masking helper ────────────────────────────────────────────────────────

    @staticmethod
    def _apply_mask(X, mask_ratio):
        """
        Zero out mask_ratio fraction of packet slots per flow.
        Returns (masked_X, mask_bool) where mask_bool.shape == (B, L).
        """
        B, L, F  = X.shape
        mask     = np.random.rand(B, L) < mask_ratio
        X_masked = X.copy()
        X_masked[mask] = 0.0           # replaced by learned [MASK] token in model
        return X_masked, mask

    # ── Model ─────────────────────────────────────────────────────────────────

    def build_model(self):
        L = self.MAX_FLOW_LEN
        d = self.D_MODEL
        F = N_FLOW_FEATURES

        inp      = layers.Input(shape=(L, F), name='flow_input')

        # Project feature vector to d_model
        x = layers.Dense(d, name='feat_proj')(inp)         # (B, L, d)
        x = x + positional_encoding(L, d)

        # Transformer encoder
        for i in range(self.NUM_LAYERS):
            attn_out = layers.MultiHeadAttention(
                num_heads=self.NUM_HEADS, key_dim=d // self.NUM_HEADS,
                name=f'attn_{i}'
            )(x, x)
            x = layers.LayerNormalization(epsilon=1e-6)(x + attn_out)
            ff_out = layers.Dense(self.FF_DIM, activation='gelu')(x)
            ff_out = layers.Dense(d)(ff_out)
            x = layers.LayerNormalization(epsilon=1e-6)(x + ff_out)

        # Decoder: reconstruct packet feature vectors
        reconstructed = layers.Dense(F, name='reconstruction')(x)   # (B, L, F)

        self.model = keras.Model(inp, reconstructed, name='FlowMAE')
        self.model.compile(optimizer=keras.optimizers.Adam(1e-3))
        self.model.summary()

    # ── Training ──────────────────────────────────────────────────────────────

    def train(self, pcap_file, epochs=30, batch_size=32):
        from sklearn.preprocessing import StandardScaler

        flows = self.extract_flows(pcap_file)
        X_raw = self.flows_to_array(flows, self.MAX_FLOW_LEN)   # (N, L, F)

        # Fit scaler on the feature axis (flatten → fit → reshape)
        N, L, F = X_raw.shape
        self.scaler = StandardScaler()
        X = self.scaler.fit_transform(X_raw.reshape(-1, F)).reshape(N, L, F)

        self.build_model()

        optimizer = keras.optimizers.Adam(1e-3)

        @tf.function
        def train_step(x_masked, x_true, mask):
            with tf.GradientTape() as tape:
                recon     = self.model(x_masked, training=True)         # (B, L, F)
                sq_err    = tf.square(x_true - recon)                   # (B, L, F)
                pkt_mse   = tf.reduce_mean(sq_err, axis=-1)             # (B, L)
                mask_f    = tf.cast(mask, tf.float32)
                loss      = tf.reduce_sum(pkt_mse * mask_f) / (tf.reduce_sum(mask_f) + 1e-8)
            grads = tape.gradient(loss, self.model.trainable_variables)
            optimizer.apply_gradients(zip(grads, self.model.trainable_variables))
            return loss

        dataset = tf.data.Dataset.from_tensor_slices(X).shuffle(5000).batch(batch_size)

        for epoch in range(epochs):
            losses = []
            for batch in dataset:
                b_np           = batch.numpy()
                masked, mask_b = self._apply_mask(b_np, self.MASK_RATIO)
                loss = train_step(
                    tf.constant(masked),
                    tf.constant(b_np),
                    tf.constant(mask_b)
                )
                losses.append(float(loss))
            print(f"Epoch {epoch+1}/{epochs}  loss={np.mean(losses):.4f}")

        # Threshold on training data
        scores = self._score_flows(X)
        self.threshold = float(np.percentile(scores, 99))
        print(f"Threshold set to {self.threshold:.6f}")

    # ── Inference ─────────────────────────────────────────────────────────────

    def _score_flows(self, X, n_masks=5):
        """
        Per-flow anomaly score: average MSE on masked positions across n_masks trials.
        Returns array of shape (N_flows,).
        """
        total = np.zeros(len(X))
        for _ in range(n_masks):
            masked, mask = self._apply_mask(X, self.MASK_RATIO)
            recon        = self.model(masked, training=False).numpy()   # (N, L, F)
            pkt_mse      = np.mean((X - recon) ** 2, axis=-1)          # (N, L)
            mask_f       = mask.astype(np.float32)
            scores       = (pkt_mse * mask_f).sum(axis=1) / (mask_f.sum(axis=1) + 1e-8)
            total       += scores
        return total / n_masks

    def detect_anomalies(self, pcap_file, threshold=None):
        flows     = self.extract_flows(pcap_file)
        X_raw     = self.flows_to_array(flows, self.MAX_FLOW_LEN)
        N, L, F   = X_raw.shape
        X         = self.scaler.transform(X_raw.reshape(-1, F)).reshape(N, L, F)
        threshold = threshold or self.threshold
        scores    = self._score_flows(X)
        anomalies = scores > threshold

        flow_keys = list(flows.keys())
        flagged   = [str(flow_keys[i]) for i in np.where(anomalies)[0]]

        results = {
            'total_flows':       len(X),
            'anomalous_flows':   int(anomalies.sum()),
            'anomaly_percentage': float(anomalies.mean() * 100),
            'flagged_flow_keys': flagged,
            'flow_scores':       scores.tolist(),
            'threshold':         threshold,
            'is_malicious':      float(anomalies.mean()) > 0.05,   # lower bar: 5% of flows
        }

        print(f"Anomalous flows: {results['anomalous_flows']}/{results['total_flows']} "
              f"({results['anomaly_percentage']:.2f}%)")
        for key in flagged[:10]:
            print(f"  Suspicious flow: {key}")
        if len(flagged) > 10:
            print(f"  ... and {len(flagged) - 10} more")
        return results

    def save_model(self, name):
        os.makedirs(MODELS_DIR, exist_ok=True)
        self.model.save(os.path.join(MODELS_DIR, f"{name}_flowmae.h5"))
        with open(os.path.join(MODELS_DIR, f"{name}_flowmae_config.pkl"), 'wb') as f:
            pickle.dump({'threshold': self.threshold, 'scaler': self.scaler}, f)

    def load_model(self, name):
        self.model = keras.models.load_model(
            os.path.join(MODELS_DIR, f"{name}_flowmae.h5"), compile=False
        )
        with open(os.path.join(MODELS_DIR, f"{name}_flowmae_config.pkl"), 'rb') as f:
            cfg            = pickle.load(f)
            self.threshold = cfg['threshold']
            self.scaler    = cfg['scaler']


# ─────────────────────────────────────────────────────────────────────────────
# Quick architecture summary (no PCAP needed)
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == '__main__':
    print("=== ByteMAE architecture ===")
    b = ByteMAE()
    b.build_model()

    print("\n=== FlowMAE architecture ===")
    f = FlowMAE()
    f.build_model()
