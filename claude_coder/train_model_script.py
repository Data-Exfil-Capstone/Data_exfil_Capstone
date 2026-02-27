"""
train_model.py
Script to continue training an existing model with additional data
"""

import argparse
from pcap_autoencoder_lib import PCAPAutoencoder

def main():
    parser = argparse.ArgumentParser(
        description='Continue training an existing PCAP autoencoder model with more data'
    )
    parser.add_argument(
        'model_name',
        help='Name of existing model to continue training'
    )
    parser.add_argument(
        'pcap_file',
        help='Path to PCAP file with additional normal/benign traffic'
    )
    parser.add_argument(
        '--epochs',
        type=int,
        default=10,
        help='Number of additional training epochs (default: 10)'
    )
    parser.add_argument(
        '--batch-size',
        type=int,
        default=32,
        help='Batch size for training (default: 32)'
    )
    parser.add_argument(
        '--validation-split',
        type=float,
        default=0.2,
        help='Fraction of data for validation (default: 0.2)'
    )
    parser.add_argument(
        '--output-name',
        help='Save as new model with this name (optional, otherwise overwrites existing)'
    )
    
    args = parser.parse_args()
    
    print("="*70)
    print("PCAP Autoencoder - Continue Training")
    print("="*70)
    print(f"\nConfiguration:")
    print(f"  Loading Model: {args.model_name}")
    print(f"  Training PCAP: {args.pcap_file}")
    print(f"  Additional Epochs: {args.epochs}")
    print(f"  Batch Size: {args.batch_size}")
    print(f"  Validation Split: {args.validation_split}")
    if args.output_name:
        print(f"  Output Model: {args.output_name}")
    else:
        print(f"  Output Model: {args.model_name} (overwrite)")
    print("\n" + "="*70 + "\n")
    
    # Load existing model
    detector = PCAPAutoencoder()
    
    try:
        print("Loading existing model...")
        detector.load_model(args.model_name)
        
        print(f"\nCurrent threshold: {detector.threshold:.6f}")
        print(f"Encoding dimension: {detector.encoding_dim}")
        
        # Continue training
        history = detector.continue_training(
            args.pcap_file,
            epochs=args.epochs,
            batch_size=args.batch_size,
            validation_split=args.validation_split
        )
        
        # Save the updated model
        output_name = args.output_name if args.output_name else args.model_name
        detector.save_model(output_name)
        
        print("\n" + "="*70)
        print("Training completed successfully!")
        print("="*70)
        print(f"\nUpdated model saved to: models/{output_name}")
        print(f"New threshold: {detector.threshold:.6f}")
        print(f"\nYou can now test traffic with:")
        print(f"  python test_model_script.py {output_name} <test.pcap>")
        
    except FileNotFoundError:
        print(f"\nError: Model '{args.model_name}' not found.")
        print("Make sure the model files exist in the models/ directory:")
        print(f"  - models/{args.model_name}_autoencoder.h5")
        print(f"  - models/{args.model_name}_scaler.pkl")
        print(f"  - models/{args.model_name}_config.pkl")
        return 1
    except Exception as e:
        print(f"\nError during training: {str(e)}")
        return 1
    
    return 0

if __name__ == "__main__":
    exit(main())
