"""
test_model.py
Script to test a trained model against benign or malicious PCAP files
"""

import argparse
import json
from pcap_autoencoder_lib import PCAPAutoencoder

def main():
    parser = argparse.ArgumentParser(
        description='Test a trained PCAP autoencoder model against traffic'
    )
    parser.add_argument(
        'model_name',
        help='Name of the trained model to use'
    )
    parser.add_argument(
        'pcap_file',
        help='Path to PCAP file to test (benign or malicious)'
    )
    parser.add_argument(
        '--threshold',
        type=float,
        help='Custom threshold for anomaly detection (optional, uses trained threshold if not specified)'
    )
    parser.add_argument(
        '--plot',
        action='store_true',
        help='Generate and display visualization plot'
    )
    parser.add_argument(
        '--save-plot',
        help='Path to save the visualization plot (e.g., results.png)'
    )
    parser.add_argument(
        '--save-results',
        help='Path to save results as JSON file (e.g., results.json)'
    )
    parser.add_argument(
        '--verbose',
        action='store_true',
        help='Show detailed information about anomalous packets'
    )
    
    args = parser.parse_args()
    
    print("="*70)
    print("PCAP Autoencoder - Test Traffic")
    print("="*70)
    print(f"\nConfiguration:")
    print(f"  Model: {args.model_name}")
    print(f"  Test PCAP: {args.pcap_file}")
    if args.threshold:
        print(f"  Custom Threshold: {args.threshold}")
    print("\n" + "="*70 + "\n")
    
    # Load model
    detector = PCAPAutoencoder()
    
    try:
        print("Loading model...")
        detector.load_model(args.model_name)
        
        print(f"Model loaded successfully!")
        print(f"  Trained threshold: {detector.threshold:.6f}")
        print(f"  Encoding dimension: {detector.encoding_dim}")
        print(f"  Features tracked: {len(detector.feature_names)}")
        
        # Test the PCAP file
        results = detector.detect_anomalies(
            args.pcap_file,
            threshold=args.threshold
        )
        
        # Display detailed results
        print("\n" + "="*70)
        print("DETECTION RESULTS")
        print("="*70)
        
        status = "🚨 SUSPICIOUS/MALICIOUS" if results['is_malicious'] else "✅ NORMAL"
        print(f"\nStatus: {status}")
        print(f"\nStatistics:")
        print(f"  Total Packets Analyzed: {results['total_packets']}")
        print(f"  Anomalous Packets: {results['anomalous_packets']}")
        print(f"  Anomaly Rate: {results['anomaly_percentage']:.2f}%")
        print(f"  Detection Threshold: {results['threshold']:.6f}")
        
        # Show verbose information
        if args.verbose and results['anomalous_packets'] > 0:
            print(f"\nAnomalous Packet Indices:")
            indices = results['anomaly_indices']
            if len(indices) <= 20:
                print(f"  {indices}")
            else:
                print(f"  First 10: {indices[:10]}")
                print(f"  Last 10: {indices[-10:]}")
                print(f"  ... ({len(indices) - 20} more)")
            
            # Show top 5 most anomalous packets
            errors = results['reconstruction_errors']
            top_indices = sorted(range(len(errors)), key=lambda i: errors[i], reverse=True)[:5]
            print(f"\nTop 5 Most Anomalous Packets:")
            for i, idx in enumerate(top_indices, 1):
                print(f"  {i}. Packet #{idx}: Error = {errors[idx]:.6f}")
        
        # Save results to JSON
        if args.save_results:
            with open(args.save_results, 'w') as f:
                json.dump(results, f, indent=2)
            print(f"\nResults saved to: {args.save_results}")
        
        # Generate plot
        if args.plot or args.save_plot:
            print("\nGenerating visualization...")
            detector.plot_reconstruction_errors(results, save_path=args.save_plot)
        
        print("\n" + "="*70)
        print("Testing completed!")
        print("="*70)
        
        # Return exit code based on detection
        return 1 if results['is_malicious'] else 0
        
    except FileNotFoundError:
        print(f"\nError: Model '{args.model_name}' not found.")
        print("Make sure the model files exist in the models/ directory:")
        print(f"  - models/{args.model_name}_autoencoder.h5")
        print(f"  - models/{args.model_name}_scaler.pkl")
        print(f"  - models/{args.model_name}_config.pkl")
        return 2
    except Exception as e:
        print(f"\nError during testing: {str(e)}")
        import traceback
        traceback.print_exc()
        return 2

if __name__ == "__main__":
    exit(main())
