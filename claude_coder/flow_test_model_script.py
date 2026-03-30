"""
flow_test_model_script.py
Test a trained FlowMAE model against a PCAP file and report anomalous flows.

Exit codes:
    0 — traffic classified as NORMAL
    1 — traffic classified as SUSPICIOUS / MALICIOUS
    2 — error (model not found, bad PCAP, etc.)

Usage:
    python flow_test_model_script.py <model_name> <test.pcap> [options]

Examples:
    python flow_test_model_script.py baseline_model suspect.pcap
    python flow_test_model_script.py baseline_model suspect.pcap --verbose --plot
    python flow_test_model_script.py baseline_model suspect.pcap --threshold 0.05 --save-results out.json
    python flow_test_model_script.py baseline_model suspect.pcap --heatmap
    python flow_test_model_script.py baseline_model suspect.pcap --heatmap --heatmap-top-n 5 --save-heatmap heatmap.png
"""

import argparse
import json
import sys
from flow_mae_lib import FlowMAE, _key_to_str


def main():
    parser = argparse.ArgumentParser(
        description='Test a trained FlowMAE model against a PCAP file'
    )
    parser.add_argument(
        'model_name',
        help='Name of the trained model to load'
    )
    parser.add_argument(
        'pcap_file',
        help='Path to PCAP file to analyse (benign or malicious)'
    )
    parser.add_argument(
        '--threshold',
        type=float,
        help='Override anomaly threshold (uses the trained threshold if omitted)'
    )
    parser.add_argument(
        '--top-n',
        type=int,
        default=10,
        help='Number of most-anomalous flows to display (default: 10)'
    )
    parser.add_argument(
        '--plot',
        action='store_true',
        help='Display per-window score bar chart'
    )
    parser.add_argument(
        '--save-plot',
        metavar='PATH',
        help='Save the score bar chart to this path (e.g. results.png)'
    )
    parser.add_argument(
        '--save-results',
        metavar='PATH',
        help='Save full results as JSON (e.g. results.json)'
    )
    parser.add_argument(
        '--verbose',
        action='store_true',
        help='Print score for every detected anomalous flow'
    )
    parser.add_argument(
        '--heatmap',
        action='store_true',
        help='Display per-feature reconstruction error heatmap for top anomalous flows'
    )
    parser.add_argument(
        '--heatmap-top-n',
        type=int,
        default=3,
        metavar='N',
        help='Number of most-anomalous flows to include in heatmap (default: 3)'
    )
    parser.add_argument(
        '--save-heatmap',
        metavar='PATH',
        help='Save the heatmap to this path (e.g. heatmap.png)'
    )

    args = parser.parse_args()

    print("=" * 70)
    print("FlowMAE — Analyse Traffic")
    print("=" * 70)
    print(f"\nConfiguration:")
    print(f"  Model    : {args.model_name}")
    print(f"  PCAP     : {args.pcap_file}")
    if args.threshold is not None:
        print(f"  Threshold: {args.threshold} (custom)")
    print("\n" + "=" * 70 + "\n")

    detector = FlowMAE()

    try:
        print("Loading model ...")
        detector.load_model(args.model_name)
        print()

        results = detector.detect_anomalies(
            args.pcap_file,
            threshold=args.threshold,
        )

        # ── Summary ──────────────────────────────────────────────────────────
        print("\n" + "=" * 70)
        print("DETECTION RESULTS")
        print("=" * 70)

        status = "SUSPICIOUS / MALICIOUS" if results['is_malicious'] else "NORMAL"
        print(f"\n  Status            : {status}")
        print(f"\n  Flows analysed    : {results['total_flows']}")
        print(f"  Anomalous flows   : {results['anomalous_flows']} "
              f"({results['anomaly_flow_pct']:.1f}%)")
        print(f"  Windows scored    : {results['total_windows']}")
        print(f"  Anomalous windows : {results['anomalous_windows']} "
              f"({results['anomaly_window_pct']:.1f}%)")
        print(f"  Threshold used    : {results['threshold']:.6f}")

        # ── Top-N most suspicious flows ───────────────────────────────────────
        flow_details = results['flow_details']
        sorted_flows = sorted(
            flow_details.items(),
            key=lambda kv: kv[1]['score'],
            reverse=True,
        )

        n_show = min(args.top_n, len(sorted_flows))
        if n_show > 0:
            print(f"\n  Top {n_show} most anomalous flows:")
            print(f"  {'Score':>10}  {'Anomalous':>9}  Flow")
            print(f"  {'-'*10}  {'-'*9}  {'-'*40}")
            for flow_str, info in sorted_flows[:n_show]:
                flag = "YES" if info['anomalous'] else "no"
                print(f"  {info['score']:>10.6f}  {flag:>9}  {flow_str}")

        # ── Verbose: all anomalous flows ──────────────────────────────────────
        if args.verbose:
            anomalous_flows = [(k, v) for k, v in sorted_flows if v['anomalous']]
            remaining = anomalous_flows[n_show:]
            if remaining:
                print(f"\n  Remaining {len(remaining)} anomalous flows:")
                for flow_str, info in remaining:
                    print(f"    {info['score']:.6f}  {flow_str}")

        # ── Save JSON ─────────────────────────────────────────────────────────
        if args.save_results:
            # window_scores can be large; include but note it
            with open(args.save_results, 'w') as f:
                json.dump(results, f, indent=2)
            print(f"\n  Results saved to: {args.save_results}")

        # ── Score bar chart ───────────────────────────────────────────────────
        if args.plot or args.save_plot:
            print("\n  Generating score plot ...")
            detector.plot_flow_scores(results, save_path=args.save_plot)

        # ── Feature heatmap ───────────────────────────────────────────────────
        if args.heatmap or args.save_heatmap:
            print(f"\n  Generating feature heatmap (top {args.heatmap_top_n} anomalous flows) ...")
            detector.plot_feature_heatmap(
                args.pcap_file,
                results,
                top_n=args.heatmap_top_n,
                save_path=args.save_heatmap,
            )

        print("\n" + "=" * 70)
        print("Analysis complete.")
        print("=" * 70)

        return 1 if results['is_malicious'] else 0

    except FileNotFoundError as e:
        print(f"\nError: {e}")
        print(f"\nExpected model files:")
        print(f"  models/{args.model_name}_flowmae.h5")
        print(f"  models/{args.model_name}_flowmae_config.pkl")
        return 2
    except ValueError as e:
        print(f"\nError: {e}")
        return 2
    except Exception as e:
        print(f"\nUnexpected error: {e}")
        import traceback
        traceback.print_exc()
        return 2


if __name__ == "__main__":
    sys.exit(main())
