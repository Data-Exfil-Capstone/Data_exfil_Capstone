"""
csv_train_model_script.py
Continue training an existing model with additional benign CSV data.

Usage:
    python csv_train_model_script.py <model_name> <csv_file> [options]

Example:
    python csv_train_model_script.py keylogger_detector \
        /path/to/clean_traffic_tcp_features.csv \
        --epochs 20 --output-name keylogger_detector_v2
"""

import argparse
from csv_autoencoder_lib import CSVAutoencoder


def main():
    parser = argparse.ArgumentParser(
        description='Continue training an existing CSV autoencoder model'
    )
    parser.add_argument('model_name', help='Name of existing model to continue training')
    parser.add_argument('csv_file',   help='Path to CSV feature file with additional benign traffic')
    parser.add_argument('--epochs', type=int, default=20,
                        help='Additional epochs (default: 20, early stopping may end sooner)')
    parser.add_argument('--batch-size', type=int, default=64,
                        help='Batch size (default: 64)')
    parser.add_argument('--validation-split', type=float, default=0.2,
                        help='Validation fraction (default: 0.2)')
    parser.add_argument('--output-name',
                        help='Save as a new model name instead of overwriting (optional)')
    args = parser.parse_args()

    print("=" * 70)
    print("CSV Autoencoder — Continue Training")
    print("=" * 70)
    print(f"\n  Loading model:  {args.model_name}")
    print(f"  CSV file:       {args.csv_file}")
    print(f"  Max epochs:     {args.epochs}")
    print(f"  Batch size:     {args.batch_size}")
    print(f"  Val split:      {args.validation_split}")
    output = args.output_name or args.model_name
    print(f"  Save as:        {output}")
    print("\n" + "=" * 70 + "\n")

    detector = CSVAutoencoder()

    try:
        detector.load_model(args.model_name)
        print(f"  Current threshold: {detector.threshold:.6f}")
        print(f"  Encoding dim:      {detector.encoding_dim}\n")

        detector.continue_training(
            args.csv_file,
            epochs=args.epochs,
            batch_size=args.batch_size,
            validation_split=args.validation_split,
        )
        detector.save_model(output)

        print("\n" + "=" * 70)
        print("Training complete!")
        print("=" * 70)
        print(f"\n  New threshold: {detector.threshold:.6f}")
        print(f"  Model saved:   models/{output}")
        print(f"\n  Test with:  python csv_test_model_script.py {output} <test.csv>")

    except FileNotFoundError:
        print(f"\nError: model '{args.model_name}' not found in models/ directory.")
        return 1
    except Exception as e:
        print(f"\nError: {e}")
        return 1

    return 0


if __name__ == "__main__":
    exit(main())
