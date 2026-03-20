"""
csv_test_model_script.py
Test a trained model against a CSV feature file (benign or malicious).

Usage:
    python csv_test_model_script.py <model_name> <csv_file> [options]

Example:
    python csv_test_model_script.py keylogger_detector \
        /path/to/dirty_decrypted_tcp_features.csv \
        --plot --save-results results.json
"""

import argparse
import json
import numpy as np
from csv_autoencoder_lib import CSVAutoencoder


def main():
    parser = argparse.ArgumentParser(
        description='Test a trained CSV autoencoder model against traffic'
    )
    parser.add_argument('model_name', help='Name of the trained model')
    parser.add_argument('csv_file',   help='Path to CSV feature file to test')
    parser.add_argument('--threshold', type=float,
                        help='Override the trained threshold (optional)')
    parser.add_argument('--plot', action='store_true',
                        help='Show reconstruction error plot')
    parser.add_argument('--save-plot',
                        help='Save plot to this path (e.g. results.png)')
    parser.add_argument('--save-results',
                        help='Save results to this JSON path (e.g. results.json)')
    parser.add_argument('--verbose', action='store_true',
                        help='Show top anomalous packet details')
    args = parser.parse_args()

    print("=" * 70)
    print("CSV Autoencoder — Test Traffic")
    print("=" * 70)
    print(f"\n  Model:    {args.model_name}")
    print(f"  CSV file: {args.csv_file}")
    if args.threshold:
        print(f"  Threshold override: {args.threshold}")
    print("\n" + "=" * 70 + "\n")

    detector = CSVAutoencoder()

    try:
        detector.load_model(args.model_name)
        print(f"  Trained threshold: {detector.threshold:.6f}")
        print(f"  Encoding dim:      {detector.encoding_dim}")
        print(f"  Features:          {detector.feature_names}\n")

        results = detector.detect_anomalies(args.csv_file, threshold=args.threshold)

        print("\n" + "=" * 70)
        print("DETECTION RESULTS")
        print("=" * 70)
        status = "SUSPICIOUS/MALICIOUS" if results['is_malicious'] else "NORMAL"
        print(f"\n  Status:            {status}")
        print(f"  Total packets:     {results['total_packets']}")
        print(f"  Anomalous:         {results['anomalous_packets']}")
        print(f"  Anomaly rate:      {results['anomaly_percentage']:.2f}%")
        print(f"  Threshold used:    {results['threshold']:.6f}")

        if args.verbose and results['anomalous_packets'] > 0:
            errors = results['reconstruction_errors']
            indices = results['anomaly_indices']
            print(f"\n  Anomalous packet indices (first 20): {indices[:20]}")
            top = sorted(range(len(errors)), key=lambda i: errors[i], reverse=True)[:5]
            print(f"\n  Top 5 highest reconstruction errors:")
            for rank, idx in enumerate(top, 1):
                print(f"    {rank}. Packet #{idx}:  error = {errors[idx]:.6f}")

        if args.save_results:
            with open(args.save_results, 'w') as f:
                json.dump(results, f, indent=2)
            print(f"\n  Results saved to: {args.save_results}")

        if args.plot or args.save_plot:
            detector.plot_reconstruction_errors(results, save_path=args.save_plot)

        print("\n" + "=" * 70)
        return 1 if results['is_malicious'] else 0

    except FileNotFoundError:
        print(f"\nError: model '{args.model_name}' not found in models/ directory.")
        return 2
    except Exception as e:
        print(f"\nError: {e}")
        import traceback
        traceback.print_exc()
        return 2


if __name__ == "__main__":
    exit(main())
