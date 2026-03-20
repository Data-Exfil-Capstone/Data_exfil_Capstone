"""
csv_create_model_script.py
Create and train a new autoencoder model from a CSV feature file.

Usage:
    python csv_create_model_script.py <csv_file> <model_name> [options]

Example:
    python csv_create_model_script.py \
        /path/to/clean_decrypted_tcp_features.csv \
        keylogger_detector \
        --encoding-dim 8 --epochs 50
"""

import argparse
from csv_autoencoder_lib import CSVAutoencoder


def main():
    parser = argparse.ArgumentParser(
        description='Create and train a new autoencoder model from a CSV feature file'
    )
    parser.add_argument('csv_file',  help='Path to CSV feature file with benign traffic')
    parser.add_argument('model_name', help='Name to save the model under')
    parser.add_argument('--encoding-dim', type=int, default=8,
                        help='Bottleneck size (default: 8)')
    parser.add_argument('--epochs', type=int, default=50,
                        help='Max training epochs — early stopping may end sooner (default: 50)')
    parser.add_argument('--batch-size', type=int, default=64,
                        help='Batch size (default: 64)')
    parser.add_argument('--validation-split', type=float, default=0.2,
                        help='Fraction held out for validation and threshold setting (default: 0.2)')
    args = parser.parse_args()

    print("=" * 70)
    print("CSV Autoencoder — Create New Model")
    print("=" * 70)
    print(f"\n  CSV file:       {args.csv_file}")
    print(f"  Model name:     {args.model_name}")
    print(f"  Encoding dim:   {args.encoding_dim}")
    print(f"  Max epochs:     {args.epochs}")
    print(f"  Batch size:     {args.batch_size}")
    print(f"  Val split:      {args.validation_split}")
    print("\n" + "=" * 70 + "\n")

    detector = CSVAutoencoder(encoding_dim=args.encoding_dim)

    try:
        history = detector.train(
            args.csv_file,
            epochs=args.epochs,
            batch_size=args.batch_size,
            validation_split=args.validation_split,
        )
        detector.save_model(args.model_name)

        print("\n" + "=" * 70)
        print("Model created and saved successfully!")
        print("=" * 70)
        print(f"\n  models/{args.model_name}_autoencoder.h5")
        print(f"  models/{args.model_name}_scaler.pkl")
        print(f"  models/{args.model_name}_config.pkl")
        print(f"\nNext steps:")
        print(f"  Continue training: python csv_train_model_script.py {args.model_name} <more_data.csv>")
        print(f"  Test traffic:      python csv_test_model_script.py  {args.model_name} <test.csv>")

    except Exception as e:
        print(f"\nError: {e}")
        return 1

    return 0


if __name__ == "__main__":
    exit(main())
