"""
create_model.py
Script to create and train a new autoencoder model from scratch
"""

import argparse
from pcap_autoencoder_lib import PCAPAutoencoder

def main():
    parser = argparse.ArgumentParser(
        description='Create and train a new PCAP autoencoder model'
    )
    parser.add_argument(
        'pcap_file',
        help='Path to PCAP file with normal/benign traffic for training'
    )
    parser.add_argument(
        'model_name',
        help='Name for the model (will create model_name_autoencoder.h5, etc.)'
    )
    parser.add_argument(
        '--encoding-dim',
        type=int,
        default=16,
        help='Dimension of encoding layer (default: 16)'
    )
    parser.add_argument(
        '--epochs',
        type=int,
        default=50,
        help='Number of training epochs (default: 50)'
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
    
    args = parser.parse_args()
    
    print("="*70)
    print("PCAP Autoencoder - Create New Model")
    print("="*70)
    print(f"\nConfiguration:")
    print(f"  Training PCAP: {args.pcap_file}")
    print(f"  Model Name: {args.model_name}")
    print(f"  Encoding Dimension: {args.encoding_dim}")
    print(f"  Epochs: {args.epochs}")
    print(f"  Batch Size: {args.batch_size}")
    print(f"  Validation Split: {args.validation_split}")
    print("\n" + "="*70 + "\n")
    
    # Initialize and train model
    detector = PCAPAutoencoder(encoding_dim=args.encoding_dim)
    
    try:
        history = detector.train(
            args.pcap_file,
            epochs=args.epochs,
            batch_size=args.batch_size,
            validation_split=args.validation_split
        )
        
        # Save the model
        detector.save_model(args.model_name)
        
        print("\n" + "="*70)
        print("Model created and saved successfully!")
        print("="*70)
        print(f"\nModel files created in models/ directory:")
        print(f"  - models/{args.model_name}_autoencoder.h5")
        print(f"  - models/{args.model_name}_scaler.pkl")
        print(f"  - models/{args.model_name}_config.pkl")
        print(f"\nYou can now:")
        print(f"  1. Train further with: python train_model_script.py {args.model_name} <more_data.pcap>")
        print(f"  2. Test traffic with: python test_model_script.py {args.model_name} <test.pcap>")
        
    except Exception as e:
        print(f"\nError during training: {str(e)}")
        return 1
    
    return 0

if __name__ == "__main__":
    exit(main())
