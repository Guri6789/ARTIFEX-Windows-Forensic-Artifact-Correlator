"""Command-Line Interface (CLI) for ARTIFEX: Insider Threat Artifact Forensics."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

# Add project root and parent to sys.path
_root = Path(__file__).resolve().parent
for _p in (_root, _root.parent):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))

from insider_forensics.core.engine import ForensicInvestigationEngine
from insider_forensics.core.models import StepStatus
from insider_forensics.test_suite.generator import generate_synthetic_scenario

# Terminal ANSI styling
C_CYAN = "\033[96m"
C_GREEN = "\033[92m"
C_WHITE = "\033[97m"
C_BOLD = "\033[1m"
C_DIM = "\033[90m"
C_RESET = "\033[0m"


def print_banner() -> None:
    banner = f"""
{C_CYAN}      ___      ______   _______  _____  ______  ______  __      __ 
     /   \\     |  _  \\ |__   __||_   _||  ____||  ____| \\ \\    / / 
    / /_\\ \\    | |_| /    | |     | |  | |__   | |__     \\ \\  / /  
   / _____ \\   |  _ <     | |     | |  |  __|  |  __|     \\ \\/ /   
  / /     \\ \\  | | \\ \\    | |    _| |_ | |     | |____    / /\\ \\   
 /_/       \\_\\ |_|  \\_\\   |_|   |_____||_|     |______|  /_/  \\_\\  {C_RESET}

  {C_BOLD}{C_WHITE}Artifact Forensics & Examination{C_RESET}
  {C_CYAN}Windows Artifact Analysis{C_RESET}  {C_DIM}|{C_RESET}  {C_CYAN}Insider Data-Theft Investigation{C_RESET}
  {C_DIM}──────────────────────────────────────────────────────────────────────────{C_RESET}
  {C_GREEN}[+]{C_RESET}  Artifact Collection & Parsing
  {C_GREEN}[+]{C_RESET}  Cross-Artifact Correlation
  {C_GREEN}[+]{C_RESET}  Data-Theft Reconstruction
  {C_GREEN}[+]{C_RESET}  Evidence-Gap Detection
  {C_GREEN}[+]{C_RESET}  Integrity Verification & Reporting
  {C_DIM}──────────────────────────────────────────────────────────────────────────{C_RESET}
  {C_DIM}Version 1.0.0  |  Digital Forensics Research Project             {C_GREEN}artifex>{C_RESET}
"""
    print(banner)


def cmd_analyze(args: argparse.Namespace, show_banner: bool = True) -> int:
    source_path = Path(args.source)
    output_path = Path(args.output)

    if not source_path.exists():
        print(f"[!] Error: Source path does not exist: {source_path}", file=sys.stderr)
        return 1

    if show_banner:
        print_banner()

    print(f"[*] Analyzing artifacts: {source_path}")
    engine = ForensicInvestigationEngine()
    result = engine.analyze_directory(source_path)

    # 1. Evidence summary
    ev_count = len(result.tracker.evidence_items)
    integrity_ok = True
    if args.verify_integrity:
        audit = result.tracker.verify_all_integrity()
        integrity_ok = all(audit.values())
    status_str = f"{C_GREEN}VERIFIED{C_RESET}" if integrity_ok else f"\033[91mTAMPERING DETECTED{C_RESET}"
    print(f"[*] Evidence Ingested:   {ev_count} artifacts (Integrity: {status_str})")

    # 2. Incident overview
    if result.hypothesis:
        hyp = result.hypothesis
        t_start = hyp.time_window_start.strftime("%Y-%m-%d %H:%M")
        t_end = hyp.time_window_end.strftime("%H:%M UTC")
        conf = hyp.confidence
        print(f"[+] Incident Summary:    User '{hyp.subject_user}' | Window: {t_start} -> {t_end}")
        print(f"[+] Threat Confidence:   {C_GREEN}{conf.score * 100:.0f}% ({conf.rating.value}){C_RESET}\n")

        print("--- Reconstructed Sequence ---")
        for step in hyp.steps:
            status_tag = f"[{step.status.value}]"
            ts_str = step.timestamp.strftime("%H:%M") if step.timestamp else "--:--"
            # Truncate description for compact view
            desc = step.description
            if len(desc) > 75:
                desc = desc[:72] + "..."
            print(f"  {step.step_number}. {step.stage.value:<22} {status_tag:<14} [{ts_str}] {desc}")
    else:
        print("[!] No complete exfiltration chain was reconstructed.")

    # 3. Anomalies (Short list)
    if result.anomalies:
        print(f"\n--- Forensic Anomalies ({len(result.anomalies)}) ---")
        for anom in result.anomalies:
            print(f"  • [{anom.severity.value:<8}] {anom.title}")

    # 4. Reports export
    engine.export_reports(result, output_path)
    print(f"\n[+] Reports Generated in: {output_path}/")
    print(f"    • Markdown: FORENSIC_REPORT.md")
    print(f"    • JSON:     forensic_findings.json")
    print(f"    • Timeline: super_timeline.csv\n")
    return 0


def cmd_simulate(args: argparse.Namespace) -> int:
    sim_dir = Path(args.workspace) / "synthetic_evidence"
    report_dir = Path(args.workspace) / "reports"
    print_banner()
    print(f"[*] Generating test scenario into: {sim_dir}")
    generate_synthetic_scenario(sim_dir)

    sub_args = argparse.Namespace(
        source=str(sim_dir),
        output=str(report_dir),
        verify_integrity=True,
    )
    return cmd_analyze(sub_args, show_banner=False)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="ARTIFEX: Windows Forensic Artifact Correlator for Insider Data Theft",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # analyze command
    analyze_parser = subparsers.add_parser("analyze", help="Analyze acquired Windows artifacts")
    analyze_parser.add_argument("--source", "-s", required=True, help="Path to evidence directory")
    analyze_parser.add_argument("--output", "-o", default="./forensic_reports", help="Output directory")
    analyze_parser.add_argument("--verify-integrity", action="store_true", default=True, help="Verify SHA-256 hashes")

    # simulate command
    sim_parser = subparsers.add_parser("simulate", help="Run realistic simulation scenario")
    sim_parser.add_argument("--workspace", "-w", default="./simulated_case", help="Workspace folder")

    args = parser.parse_args()
    if args.command == "analyze":
        sys.exit(cmd_analyze(args))
    elif args.command == "simulate":
        sys.exit(cmd_simulate(args))


if __name__ == "__main__":
    main()
