"""
pcap_autoencoder_lib.py
Core library for PCAP-based autoencoder anomaly detection
"""

import os
import numpy as np
import pandas as pd
from scapy.all import rdpcap, IP, TCP, UDP, ICMP
from sklearn.preprocessing import StandardScaler
import tensorflow as tf
from tensorflow import keras
from tensorflow.keras import layers
import matplotlib.pyplot as plt
import pickle

# Directory where models are stored
MODELS_DIR = "models"

class PCAPAutoencoder:
    def __init__(self, encoding_dim=16):
        """
        Initialize the PCAP Autoencoder for network traffic anomaly detection.
        
        Args:
            encoding_dim: Dimension of the encoded representation
        """
        self.encoding_dim = encoding_dim
        self.autoencoder = None
        self.encoder = None
        self.scaler = StandardScaler()
        self.feature_names = []
        self.threshold = None
        
    def extract_features(self, pcap_file):
        """
        Extract relevant features from PCAP file.
        
        Args:
            pcap_file: Path to PCAP file
            
        Returns:
            DataFrame with extracted features
        """
        packets = rdpcap(pcap_file)
        features = []
        
        for pkt in packets:
            feature_dict = {}
            
            # Basic packet features
            feature_dict['packet_length'] = len(pkt)
            
            # IP layer features
            if IP in pkt:
                feature_dict['ip_version'] = pkt[IP].version
                feature_dict['ip_ihl'] = pkt[IP].ihl
                feature_dict['ip_tos'] = pkt[IP].tos
                feature_dict['ip_len'] = pkt[IP].len
                feature_dict['ip_flags'] = int(pkt[IP].flags)
                feature_dict['ip_ttl'] = pkt[IP].ttl
                feature_dict['ip_proto'] = pkt[IP].proto
            else:
                feature_dict['ip_version'] = 0
                feature_dict['ip_ihl'] = 0
                feature_dict['ip_tos'] = 0
                feature_dict['ip_len'] = 0
                feature_dict['ip_flags'] = 0
                feature_dict['ip_ttl'] = 0
                feature_dict['ip_proto'] = 0
            
            # TCP layer features
            if TCP in pkt:
                feature_dict['tcp_sport'] = pkt[TCP].sport
                feature_dict['tcp_dport'] = pkt[TCP].dport
                feature_dict['tcp_seq'] = pkt[TCP].seq
                feature_dict['tcp_ack'] = pkt[TCP].ack
                feature_dict['tcp_dataofs'] = pkt[TCP].dataofs
                feature_dict['tcp_flags'] = int(pkt[TCP].flags)
                feature_dict['tcp_window'] = pkt[TCP].window
                feature_dict['is_tcp'] = 1
                feature_dict['is_udp'] = 0
            elif UDP in pkt:
                feature_dict['tcp_sport'] = pkt[UDP].sport
                feature_dict['tcp_dport'] = pkt[UDP].dport
                feature_dict['tcp_seq'] = 0
                feature_dict['tcp_ack'] = 0
                feature_dict['tcp_dataofs'] = 0
                feature_dict['tcp_flags'] = 0
                feature_dict['tcp_window'] = 0
                feature_dict['is_tcp'] = 0
                feature_dict['is_udp'] = 1
            else:
                feature_dict['tcp_sport'] = 0
                feature_dict['tcp_dport'] = 0
                feature_dict['tcp_seq'] = 0
                feature_dict['tcp_ack'] = 0
                feature_dict['tcp_dataofs'] = 0
                feature_dict['tcp_flags'] = 0
                feature_dict['tcp_window'] = 0
                feature_dict['is_tcp'] = 0
                feature_dict['is_udp'] = 0
            
            # ICMP features
            feature_dict['is_icmp'] = 1 if ICMP in pkt else 0
            
            features.append(feature_dict)
        
        df = pd.DataFrame(features)
        self.feature_names = df.columns.tolist()
        return df
    
    def build_model(self, input_dim):
        """
        Build the autoencoder model architecture.
        
        Args:
            input_dim: Number of input features
        """
        # Encoder
        input_layer = layers.Input(shape=(input_dim,))
        encoded = layers.Dense(64, activation='relu')(input_layer)
        encoded = layers.Dropout(0.2)(encoded)
        encoded = layers.Dense(32, activation='relu')(encoded)
        encoded = layers.Dense(self.encoding_dim, activation='relu')(encoded)
        
        # Decoder
        decoded = layers.Dense(32, activation='relu')(encoded)
        decoded = layers.Dense(64, activation='relu')(decoded)
        decoded = layers.Dropout(0.2)(decoded)
        decoded = layers.Dense(input_dim, activation='sigmoid')(decoded)
        
        # Autoencoder model
        self.autoencoder = keras.Model(input_layer, decoded)
        self.encoder = keras.Model(input_layer, encoded)
        
        self.autoencoder.compile(optimizer='adam', loss='mse', metrics=['mae'])
        
    def train(self, pcap_file, epochs=50, batch_size=32, validation_split=0.2):
        """
        Train the autoencoder on normal traffic.
        
        Args:
            pcap_file: Path to PCAP file containing normal traffic
            epochs: Number of training epochs
            batch_size: Batch size for training
            validation_split: Fraction of data to use for validation
        """
        print(f"Extracting features from {pcap_file}...")
        df = self.extract_features(pcap_file)
        
        # Normalize features
        X = self.scaler.fit_transform(df)
        
        # Build model
        self.build_model(X.shape[1])
        
        print(f"Training autoencoder on {len(X)} packets...")
        history = self.autoencoder.fit(
            X, X,
            epochs=epochs,
            batch_size=batch_size,
            validation_split=validation_split,
            shuffle=True,
            verbose=1
        )
        
        # Calculate reconstruction error threshold
        reconstructions = self.autoencoder.predict(X)
        mse = np.mean(np.power(X - reconstructions, 2), axis=1)
        self.threshold = np.percentile(mse, 95)  # 95th percentile
        
        print(f"\nTraining complete!")
        print(f"Anomaly threshold set to: {self.threshold:.6f}")
        
        return history
    
    def continue_training(self, pcap_file, epochs=10, batch_size=32, validation_split=0.2):
        """
        Continue training an existing model with additional data.
        
        Args:
            pcap_file: Path to PCAP file with additional normal traffic
            epochs: Number of additional training epochs
            batch_size: Batch size for training
            validation_split: Fraction of data to use for validation
        """
        if self.autoencoder is None:
            raise ValueError("No model to continue training. Use train() first or load a model.")
        
        print(f"Extracting features from {pcap_file}...")
        df = self.extract_features(pcap_file)
        
        # Transform using existing scaler
        X = self.scaler.transform(df)
        
        print(f"Continuing training on {len(X)} packets...")
        history = self.autoencoder.fit(
            X, X,
            epochs=epochs,
            batch_size=batch_size,
            validation_split=validation_split,
            shuffle=True,
            verbose=1
        )
        
        # Recalculate threshold with new data
        reconstructions = self.autoencoder.predict(X)
        mse = np.mean(np.power(X - reconstructions, 2), axis=1)
        self.threshold = np.percentile(mse, 95)
        
        print(f"\nContinued training complete!")
        print(f"Updated anomaly threshold: {self.threshold:.6f}")
        
        return history
    
    def detect_anomalies(self, pcap_file, threshold=None):
        """
        Detect anomalies in test PCAP file.
        
        Args:
            pcap_file: Path to PCAP file to test
            threshold: Custom threshold (uses trained threshold if None)
            
        Returns:
            Dictionary with detection results
        """
        if self.autoencoder is None:
            raise ValueError("Model not trained. Call train() first or load a model.")
        
        if threshold is None:
            threshold = self.threshold
        
        print(f"\nAnalyzing {pcap_file}...")
        df = self.extract_features(pcap_file)
        X = self.scaler.transform(df)
        
        # Get reconstructions and calculate errors
        reconstructions = self.autoencoder.predict(X, verbose=0)
        mse = np.mean(np.power(X - reconstructions, 2), axis=1)
        
        # Identify anomalies
        anomalies = mse > threshold
        anomaly_indices = np.where(anomalies)[0]
        
        results = {
            'total_packets': len(X),
            'anomalous_packets': int(np.sum(anomalies)),
            'anomaly_percentage': float(np.sum(anomalies) / len(X) * 100),
            'anomaly_indices': anomaly_indices.tolist(),
            'reconstruction_errors': mse.tolist(),
            'threshold': threshold,
            'is_malicious': np.sum(anomalies) / len(X) > 0.1  # >10% anomalies
        }
        
        print(f"\nResults:")
        print(f"Total packets: {results['total_packets']}")
        print(f"Anomalous packets: {results['anomalous_packets']}")
        print(f"Anomaly rate: {results['anomaly_percentage']:.2f}%")
        print(f"Classification: {'SUSPICIOUS/MALICIOUS' if results['is_malicious'] else 'NORMAL'}")
        
        return results
    
    def plot_reconstruction_errors(self, results, save_path=None):
        """
        Plot reconstruction errors for visualization.
        
        Args:
            results: Results dictionary from detect_anomalies()
            save_path: Path to save plot (optional)
        """
        errors = results['reconstruction_errors']
        threshold = results['threshold']
        
        plt.figure(figsize=(12, 6))
        plt.plot(errors, label='Reconstruction Error', alpha=0.7)
        plt.axhline(y=threshold, color='r', linestyle='--', label=f'Threshold ({threshold:.6f})')
        plt.xlabel('Packet Index')
        plt.ylabel('Reconstruction Error (MSE)')
        plt.title('Packet Reconstruction Errors')
        plt.legend()
        plt.grid(True, alpha=0.3)
        
        if save_path:
            plt.savefig(save_path, dpi=300, bbox_inches='tight')
            print(f"Plot saved to {save_path}")
        
        plt.tight_layout()
        plt.show()
    
    def save_model(self, model_name):
        """Save the trained model and scaler to the models directory."""
        # Create models directory if it doesn't exist
        os.makedirs(MODELS_DIR, exist_ok=True)

        path_prefix = os.path.join(MODELS_DIR, model_name)
        self.autoencoder.save(f"{path_prefix}_autoencoder.h5")
        with open(f"{path_prefix}_scaler.pkl", 'wb') as f:
            pickle.dump(self.scaler, f)
        with open(f"{path_prefix}_config.pkl", 'wb') as f:
            pickle.dump({
                'threshold': self.threshold,
                'feature_names': self.feature_names,
                'encoding_dim': self.encoding_dim
            }, f)
        print(f"Model saved to: {MODELS_DIR}/{model_name}")
    
    def load_model(self, model_name):
        """Load a trained model and scaler from the models directory."""
        path_prefix = os.path.join(MODELS_DIR, model_name)
        self.autoencoder = keras.models.load_model(f"{path_prefix}_autoencoder.h5", compile=False)
        self.autoencoder.compile(optimizer='adam', loss='mse')
        with open(f"{path_prefix}_scaler.pkl", 'rb') as f:
            self.scaler = pickle.load(f)
        with open(f"{path_prefix}_config.pkl", 'rb') as f:
            config = pickle.load(f)
            self.threshold = config['threshold']
            self.feature_names = config['feature_names']
            self.encoding_dim = config['encoding_dim']
        print(f"Model loaded from: {MODELS_DIR}/{model_name}")
