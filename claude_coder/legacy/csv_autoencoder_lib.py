"""
csv_autoencoder_lib.py
Autoencoder anomaly detection using pre-extracted CSV feature files.
Incorporates architecture improvements over the pcap-based version:
  - linear output activation (features are StandardScaler output, not [0,1])
  - smaller encoding_dim (tighter bottleneck for 10-feature input)
  - dropout on decoder side only
  - threshold set on held-out validation data, not training data
"""

import os
import numpy as np
import pandas as pd
from sklearn.preprocessing import StandardScaler
import tensorflow as tf
from tensorflow import keras
from tensorflow.keras import layers
import matplotlib.pyplot as plt
import pickle

MODELS_DIR = "models"

EXPECTED_COLUMNS = [
    'inter_arrival_time',
    'packet_length',
    'ip_ttl',
    'ip_flags',
    'ip_len',
    'tcp_dport',
    'tcp_dataofs',
    'tcp_flags',
    'tcp_window',
    'payload_len',
]


class CSVAutoencoder:
    def __init__(self, encoding_dim=8):
        """
        Args:
            encoding_dim: Bottleneck size. 8 works well for 10 input features.
                          Smaller = tighter compression = more sensitive to anomalies.
        """
        self.encoding_dim = encoding_dim
        self.autoencoder = None
        self.encoder = None
        self.scaler = StandardScaler()
        self.threshold = None
        self.feature_names = EXPECTED_COLUMNS[:]

    def _load_csv(self, csv_file):
        df = pd.read_csv(csv_file)
        missing = [c for c in EXPECTED_COLUMNS if c not in df.columns]
        if missing:
            raise ValueError(f"CSV is missing columns: {missing}")
        return df[EXPECTED_COLUMNS].astype(float)

    def build_model(self, input_dim):
        input_layer = layers.Input(shape=(input_dim,))

        # Encoder — no dropout here so the bottleneck stays clean
        x = layers.Dense(32, activation='relu')(input_layer)
        x = layers.Dense(16, activation='relu')(x)
        encoded = layers.Dense(self.encoding_dim, activation='relu')(x)

        # Decoder — dropout here regularises reconstruction
        x = layers.Dense(16, activation='relu')(encoded)
        x = layers.Dropout(0.2)(x)
        x = layers.Dense(32, activation='relu')(x)
        x = layers.Dropout(0.2)(x)
        # linear activation: StandardScaler output is unbounded, sigmoid would distort it
        decoded = layers.Dense(input_dim, activation='linear')(x)

        self.autoencoder = keras.Model(input_layer, decoded)
        self.encoder = keras.Model(input_layer, encoded)
        self.autoencoder.compile(optimizer='adam', loss='mse', metrics=['mae'])

    def train(self, csv_file, epochs=50, batch_size=64, validation_split=0.2):
        """
        Train on benign CSV feature file.
        Threshold is calculated on the validation split so it reflects
        held-out data rather than the training set.
        """
        print(f"Loading features from {csv_file}...")
        df = self._load_csv(csv_file)
        X = self.scaler.fit_transform(df)

        self.build_model(X.shape[1])
        print(f"Training on {len(X)} packets  |  input_dim={X.shape[1]}  |  encoding_dim={self.encoding_dim}")

        history = self.autoencoder.fit(
            X, X,
            epochs=epochs,
            batch_size=batch_size,
            validation_split=validation_split,
            shuffle=True,
            verbose=1,
            callbacks=[
                keras.callbacks.EarlyStopping(
                    monitor='val_loss', patience=5, restore_best_weights=True
                )
            ]
        )

        # Set threshold on the validation portion only (last validation_split fraction)
        n_val = int(len(X) * validation_split)
        X_val = X[-n_val:]
        val_recon = self.autoencoder.predict(X_val, verbose=0)
        val_mse = np.mean(np.power(X_val - val_recon, 2), axis=1)
        self.threshold = float(np.percentile(val_mse, 99))

        print(f"\nTraining complete — anomaly threshold (99th pct on val): {self.threshold:.6f}")
        return history

    def continue_training(self, csv_file, epochs=10, batch_size=64, validation_split=0.2):
        if self.autoencoder is None:
            raise ValueError("No model loaded. Call train() or load_model() first.")

        print(f"Loading features from {csv_file}...")
        df = self._load_csv(csv_file)
        X = self.scaler.transform(df)

        print(f"Continuing training on {len(X)} packets...")
        history = self.autoencoder.fit(
            X, X,
            epochs=epochs,
            batch_size=batch_size,
            validation_split=validation_split,
            shuffle=True,
            verbose=1,
            callbacks=[
                keras.callbacks.EarlyStopping(
                    monitor='val_loss', patience=5, restore_best_weights=True
                )
            ]
        )

        n_val = int(len(X) * validation_split)
        X_val = X[-n_val:]
        val_recon = self.autoencoder.predict(X_val, verbose=0)
        val_mse = np.mean(np.power(X_val - val_recon, 2), axis=1)
        self.threshold = float(np.percentile(val_mse, 99))

        print(f"\nUpdated threshold: {self.threshold:.6f}")
        return history

    def detect_anomalies(self, csv_file, threshold=None):
        if self.autoencoder is None:
            raise ValueError("No model loaded. Call train() or load_model() first.")

        threshold = threshold if threshold is not None else self.threshold

        print(f"Analyzing {csv_file}...")
        df = self._load_csv(csv_file)
        X = self.scaler.transform(df)

        reconstructions = self.autoencoder.predict(X, verbose=0)
        mse = np.mean(np.power(X - reconstructions, 2), axis=1)
        anomalies = mse > threshold

        results = {
            'total_packets': len(X),
            'anomalous_packets': int(np.sum(anomalies)),
            'anomaly_percentage': float(np.sum(anomalies) / len(X) * 100),
            'anomaly_indices': np.where(anomalies)[0].tolist(),
            'reconstruction_errors': mse.tolist(),
            'threshold': threshold,
            'is_malicious': float(np.sum(anomalies) / len(X)) > 0.1,
        }

        print(f"\nResults:")
        print(f"  Total packets:     {results['total_packets']}")
        print(f"  Anomalous:         {results['anomalous_packets']}")
        print(f"  Anomaly rate:      {results['anomaly_percentage']:.2f}%")
        print(f"  Classification:    {'SUSPICIOUS/MALICIOUS' if results['is_malicious'] else 'NORMAL'}")

        return results

    def plot_reconstruction_errors(self, results, save_path=None):
        errors = results['reconstruction_errors']
        threshold = results['threshold']

        plt.figure(figsize=(14, 5))
        plt.plot(errors, label='Reconstruction Error', alpha=0.6, linewidth=0.5)
        plt.axhline(y=threshold, color='r', linestyle='--',
                    label=f'Threshold ({threshold:.6f})')
        plt.xlabel('Packet Index')
        plt.ylabel('Reconstruction Error (MSE)')
        plt.title('Packet Reconstruction Errors')
        plt.legend()
        plt.grid(True, alpha=0.3)
        plt.tight_layout()

        if save_path:
            plt.savefig(save_path, dpi=300, bbox_inches='tight')
            print(f"Plot saved to {save_path}")
        plt.show()

    def save_model(self, model_name):
        os.makedirs(MODELS_DIR, exist_ok=True)
        prefix = os.path.join(MODELS_DIR, model_name)
        self.autoencoder.save(f"{prefix}_autoencoder.h5")
        with open(f"{prefix}_scaler.pkl", 'wb') as f:
            pickle.dump(self.scaler, f)
        with open(f"{prefix}_config.pkl", 'wb') as f:
            pickle.dump({
                'threshold': self.threshold,
                'feature_names': self.feature_names,
                'encoding_dim': self.encoding_dim,
            }, f)
        print(f"Model saved: {MODELS_DIR}/{model_name}")

    def load_model(self, model_name):
        prefix = os.path.join(MODELS_DIR, model_name)
        self.autoencoder = keras.models.load_model(
            f"{prefix}_autoencoder.h5", compile=False
        )
        self.autoencoder.compile(optimizer='adam', loss='mse', metrics=['mae'])
        with open(f"{prefix}_scaler.pkl", 'rb') as f:
            self.scaler = pickle.load(f)
        with open(f"{prefix}_config.pkl", 'rb') as f:
            config = pickle.load(f)
            self.threshold = config['threshold']
            self.feature_names = config['feature_names']
            self.encoding_dim = config['encoding_dim']
        print(f"Model loaded: {MODELS_DIR}/{model_name}")
