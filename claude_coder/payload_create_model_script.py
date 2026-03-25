"""
payload_create_model_script.py
Create and train a new PayloadMAE model from scratch using a decrypted benign PCAP.

Requires a PCAP with decrypted payloads.  If your traffic is TLS-encrypted,
pre-decrypt it first with tshark and your TLS key log file:

    tshark -r encrypted.pcap -o tls.keylog_file:keys.log -w decrypted.pcap

Usage:
    python payload_create_model_script.py <benign_decrypted.pcap> <model_name> [options]

Examples:
    python payload_create_model_script.py clean_decrypted.pcap payload_baseline
    python payload_create_model_script.py clean_decrypted.pcap payload_baseline --epochs 50
"""

import argparse
import sys
from payload_mae_lib import PayloadMAE


def main():
    parser = argparse.ArgumentParser(
        description='Create and train a new PayloadMAE model from a decrypted benign PCAP'
    )
    parser.add_argument(
        'pcap_file',
        help='Path to decrypted PCAP file containing normal/benign traffic for training'
    )
    parser.add_argument(
        'model_name',
        help='Name for the saved model (e.g. "baseline" creates models/baseline_payloadmae.*)'
    )
    parser.add_argument(
        '--epochs',
        type=int,
        default=30,
        help='Maximum training epochs — early stopping may end sooner (default: 30)'
    )
    parser.add_argument(
        '--batch-size',
        type=int,
        default=32,
        help='Batch size for training (default: 32)'
    )
    parser.add_argument(
        '--max-flow-len',
        type=int,
        default=32,
        help='Packets per flow window — longer flows are split (default: 32)'
    )
    parser.add_argument(
        '--min-flow-len',
        type=int,
        default=4,
        help='Minimum packets to keep a flow (default: 4)'
    )
    parser.add_argument(
        '--mask-ratio',
        type=float,
        default=0.40,
        help='Fraction of packet slots masked during training (default: 0.40)'
    )
    parser.add_argument(
        '--d-model',
        type=int,
        default=32,
        help='Transformer hidden dimension (default: 32)'
    )
    parser.add_argument(
        '--num-layers',
        type=int,
        default=2,
        help='Number of Transformer encoder blocks (default: 2)'
    )

    args = parser.parse_args()

    print("=" * 70)
    print("PayloadMAE — Create New Model")
    print("=" * 70)
    print(f"\nConfiguration:")
    print(f"  Training PCAP : {args.pcap_file}")
    print(f"  Model name    : {args.model_name}")
    print(f"  Epochs        : {args.epochs}")
    print(f"  Batch size    : {args.batch_size}")
    print(f"  Max flow len  : {args.max_flow_len} packets")
    print(f"  Min flow len  : {args.min_flow_len} packets")
    print(f"  Mask ratio    : {args.mask_ratio:.0%}")
    print(f"  d_model       : {args.d_model}")
    print(f"  Num layers    : {args.num_layers}")
    print(f"\n  Features per packet: 14 (8 metadata + 6 payload statistics)")
    print("\n" + "=" * 70 + "\n")

    detector = PayloadMAE()
    detector.MAX_FLOW_LEN = args.max_flow_len
    detector.MIN_FLOW_LEN = args.min_flow_len
    detector.MASK_RATIO   = args.mask_ratio
    detector.D_MODEL      = args.d_model
    detector.NUM_LAYERS   = args.num_layers

    try:
        detector.train(
            args.pcap_file,
            epochs=args.epochs,
            batch_size=args.batch_size,
        )
        detector.save_model(args.model_name)

        print("\n" + "=" * 70)
        print("Model created and saved successfully!")
        print("=" * 70)
        print(f"\nFiles written to models/:")
        print(f"  models/{args.model_name}_payloadmae.weights.h5")
        print(f"  models/{args.model_name}_payloadmae_config.pkl")
        print(f"\nNext steps:")
        print(f"  Train further : python payload_train_model_script.py {args.model_name} <more.pcap>")
        print(f"  Test traffic  : python payload_test_model_script.py  {args.model_name} <test.pcap>")

    except FileNotFoundError as e:
        print(f"\nError: {e}")
        return 1
    except ValueError as e:
        print(f"\nError: {e}")
        print("The PCAP may contain too few packets or flows to train on.")
        return 1
    except Exception as e:
        print(f"\nUnexpected error: {e}")
        import traceback
        traceback.print_exc()
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
