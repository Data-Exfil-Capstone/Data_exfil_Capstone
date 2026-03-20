"""
flow_train_model_script.py
Continue training an existing FlowMAE model with additional benign PCAP data.

The scaler is NOT re-fitted — new data is projected into the same feature
space. The anomaly threshold is recalculated from the new data after training.

Usage:
    python flow_train_model_script.py <model_name> <more_benign.pcap> [options]

Example:
    python flow_train_model_script.py baseline_model more_normal.pcap
    python flow_train_model_script.py baseline_model more_normal.pcap --epochs 15 --output-name baseline_v2
"""

import argparse
import sys
from flow_mae_lib import FlowMAE


def main():
    parser = argparse.ArgumentParser(
        description='Continue training an existing FlowMAE model with additional PCAP data'
    )
    parser.add_argument(
        'model_name',
        help='Name of the existing model to continue training'
    )
    parser.add_argument(
        'pcap_file',
        help='Path to PCAP file with additional benign/normal traffic'
    )
    parser.add_argument(
        '--epochs',
        type=int,
        default=10,
        help='Additional training epochs — early stopping may end sooner (default: 10)'
    )
    parser.add_argument(
        '--batch-size',
        type=int,
        default=32,
        help='Batch size (default: 32)'
    )
    parser.add_argument(
        '--output-name',
        help='Save updated model under a new name (default: overwrites the loaded model)'
    )

    args = parser.parse_args()

    print("=" * 70)
    print("FlowMAE — Continue Training")
    print("=" * 70)
    print(f"\nConfiguration:")
    print(f"  Model         : {args.model_name}")
    print(f"  Training PCAP : {args.pcap_file}")
    print(f"  Epochs        : {args.epochs}")
    print(f"  Batch size    : {args.batch_size}")
    output_name = args.output_name or args.model_name
    print(f"  Output model  : {output_name}"
          + (" (new)" if args.output_name else " (overwrite)"))
    print("\n" + "=" * 70 + "\n")

    detector = FlowMAE()

    try:
        print("Loading model ...")
        detector.load_model(args.model_name)
        print(f"  Current threshold : {detector.threshold:.6f}")

        detector.continue_training(
            args.pcap_file,
            epochs=args.epochs,
            batch_size=args.batch_size,
        )

        detector.save_model(output_name)

        print("\n" + "=" * 70)
        print("Training completed successfully!")
        print("=" * 70)
        print(f"\nUpdated model : models/{output_name}")
        print(f"New threshold : {detector.threshold:.6f}")
        print(f"\nTest traffic with:")
        print(f"  python flow_test_model_script.py {output_name} <test.pcap>")

    except FileNotFoundError as e:
        print(f"\nError: {e}")
        print(f"\nExpected files in models/:")
        print(f"  models/{args.model_name}_flowmae.h5")
        print(f"  models/{args.model_name}_flowmae_config.pkl")
        return 1
    except ValueError as e:
        print(f"\nError: {e}")
        return 1
    except Exception as e:
        print(f"\nUnexpected error: {e}")
        import traceback
        traceback.print_exc()
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
