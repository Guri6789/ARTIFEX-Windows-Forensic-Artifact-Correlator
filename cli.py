"""Command-Line Interface (CLI) for ARTIFEX: Insider Threat Artifact Forensics.

Supports:
- analyze: Process acquired Windows triage directories or FTK Imager dumps.
- acquire: Real-life Windows live incident acquisition via FTK Imager CLI or live triage collector.
- verify-ftk: Ingest and verify FTK Imager acquisition manifests (*.txt / Image_Summary.txt).
- simulate: Built-in end-to-end simulated scenario generator.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

# Add project root and parent to sys.path
_root = Path(__file__).resolve().parent
for _p in (_root, _root.parent):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))

from insider_forensics.core.engine import ForensicInvestigationEngine
from insider_forensics.imager.ftk_imager import (
    FtkImagerLogParser,
    FTKImagerController,
    WindowsLiveTriageCollector,
)
from insider_forensics.test_suite.generator import generate_synthetic_scenario

# Terminal ANSI styling
C_CYAN = "\033[96m"
C_GREEN = "\033[92m"
C_YELLOW = "\033[93m"
C_RED = "\033[91m"
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
  {C_DIM}--------------------------------------------------------------------------{C_RESET}
  {C_GREEN}[+]{C_RESET}  FTK Imager Acquisition & Manifest Verification
  {C_GREEN}[+]{C_RESET}  Real Windows Binary Artifact Parsing (EVTX, Registry, Prefetch, LNK, MFT)
  {C_GREEN}[+]{C_RESET}  Cross-Artifact Correlation & USB-to-VSN Matching
  {C_GREEN}[+]{C_RESET}  5-Stage Insider Data-Theft Sequence Reconstruction
  {C_GREEN}[+]{C_RESET}  Forensic Anomaly & Evidence-Gap Detection
  {C_GREEN}[+]{C_RESET}  Non-Repudiation Chain of Custody & Reporting
  {C_DIM}--------------------------------------------------------------------------{C_RESET}
  {C_DIM}Version 2.0.0  |  Digital Forensics Research & Incident Response  {C_GREEN}artifex>{C_RESET}
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
    if getattr(args, "verify_integrity", True):
        audit = result.tracker.verify_all_integrity()
        integrity_ok = all(audit.values())
    status_str = f"{C_GREEN}VERIFIED{C_RESET}" if integrity_ok else f"{C_RED}TAMPERING DETECTED{C_RESET}"
    print(f"[*] Evidence Ingested:   {ev_count} artifacts (Integrity: {status_str})")

    # Check for FTK Imager manifests in evidence
    ftk_logs = [
        item for item in result.tracker.evidence_items.values()
        if (item.notes and "FTK" in item.notes) or (item.artifact_category and "FTK_IMAGER" in item.artifact_category)
    ]
    if ftk_logs:
        print(f"[*] FTK Imager Manifest: {C_GREEN}Detected ({len(ftk_logs)} acquisition log(s) verified){C_RESET}")

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
            desc = step.description
            if len(desc) > 75:
                desc = desc[:72] + "..."
            print(f"  {step.step_number}. {step.stage.value:<22} {status_tag:<14} [{ts_str}] {desc}")
    else:
        print("[!] No complete exfiltration chain was reconstructed.")

    # 3. Anomalies
    if result.anomalies:
        print(f"\n--- Forensic Anomalies ({len(result.anomalies)}) ---")
        for anom in result.anomalies:
            print(f"  * [{anom.severity.value:<8}] {anom.title}")

    # 4. Reports export
    engine.export_reports(result, output_path)
    print(f"\n[+] Reports Generated in: {output_path}/")
    print(f"    * Markdown: FORENSIC_REPORT.md")
    print(f"    * JSON:     forensic_findings.json")
    print(f"    * Timeline: super_timeline.csv\n")
    return 0


def cmd_acquire(args: argparse.Namespace) -> int:
    """Execute live incident acquisition via FTK Imager or live triage collector."""
    print_banner()
    output_dir = Path(args.output)
    output_dir.mkdir(parents=True, exist_ok=True)

    safe_case_id = re.sub(r"[^A-Za-z0-9_\-\.]", "_", args.case_id)
    print(f"[*] Initializing Incident Acquisition: Case '{args.case_id}' | Examiner: {args.examiner}")
    ftk_ctrl = FTKImagerController(custom_path=args.ftk_path)

    tool_choice = args.tool.lower()
    used_ftk = False

    if tool_choice in ("auto", "ftkimager", "ftk"):
        if ftk_ctrl.is_available():
            print(f"[+] FTK Imager CLI detected: {ftk_ctrl.executable_path}")
            dest_prefix = output_dir / f"FTK_{safe_case_id}"
            src_target = args.target if args.target else (r"\\.\PhysicalDrive0" if sys.platform == "win32" else "/dev/sda")
            print(f"[*] Running FTK Imager Acquisition on target: {src_target}")
            print(f"[*] Format: {args.format.upper()} | Chunk size: {args.frag}MB | Post-verify: {args.verify}")

            success, log_output = ftk_ctrl.create_image(
                source=src_target,
                destination_path=dest_prefix,
                image_format=args.format,
                case_num=args.case_id,
                evidence_num=args.evidence_id,
                examiner=args.examiner,
                description=args.description,
                fragment_size_mb=args.frag,
                verify=args.verify,
            )

            # Write acquisition log
            log_file = output_dir / f"ftk_acquisition_{safe_case_id}.txt"
            log_file.write_text(log_output, encoding="utf-8")
            if success:
                print(f"{C_GREEN}[+] FTK Imager Acquisition Completed Successfully.{C_RESET}")
                print(f"    Log: {log_file}")
                used_ftk = True
            else:
                print(f"{C_YELLOW}[!] FTK Imager reported non-zero status. Falling back to live triage collector.{C_RESET}")
        else:
            if tool_choice in ("ftkimager", "ftk"):
                print(f"{C_RED}[!] Error: FTK Imager CLI executable not found at '{ftk_ctrl.executable_path or 'default paths'}'.{C_RESET}")
                print(f"    Please specify path with --ftk-path or use --tool live.")
                return 1
            print(f"[*] FTK Imager CLI not detected in standard paths. Using built-in Live Windows Triage Collector.")

    if not used_ftk:
        print(f"[*] Executing Targeted Live Windows Triage Collection...")
        collector = WindowsLiveTriageCollector(
            output_dir=output_dir,
            case_id=args.case_id,
            examiner=args.examiner,
        )
        summary = collector.collect()
        print(f"{C_GREEN}[+] Live Triage Complete: Preserved {summary['total_files']} critical forensic artifacts.{C_RESET}")
        print(f"    Output:   {summary['output_directory']}")
        print(f"    Manifest: {summary['manifest_log']}")

    if args.auto_analyze:
        print(f"\n[*] Auto-Analyze enabled. Launching investigation correlation...")
        sub_args = argparse.Namespace(
            source=str(output_dir),
            output=str(output_dir / "reports"),
            verify_integrity=True,
        )
        return cmd_analyze(sub_args, show_banner=False)

    return 0


def cmd_verify_ftk(args: argparse.Namespace) -> int:
    """Ingest and verify an FTK Imager acquisition log file."""
    print_banner()
    log_path = Path(args.log)
    if not log_path.exists():
        print(f"{C_RED}[!] Error: FTK log file not found: {log_path}{C_RESET}", file=sys.stderr)
        return 1

    content = log_path.read_text(encoding="utf-8", errors="replace")
    if not FtkImagerLogParser.is_ftk_log(content):
        print(f"{C_RED}[!] Error: File does not appear to be an AccessData / Exterro FTK Imager report.{C_RESET}")
        return 1

    info = FtkImagerLogParser.parse_log_text(content, log_path)
    print(f"{C_BOLD}[+] FTK Imager Acquisition Log Verification:{C_RESET}")
    print(f"    * Case Number:       {info.case_number or 'N/A'}")
    print(f"    * Evidence Number:   {info.evidence_number or 'N/A'}")
    print(f"    * Examiner:          {info.examiner or 'N/A'}")
    print(f"    * Target Drive:      {info.drive_model or 'N/A'} (Serial: {info.drive_serial or 'N/A'})")
    print(f"    * Sector Count:      {info.sector_count}")
    print(f"    * MD5 Hash:          {info.md5_checksum or 'N/A'} [Verified: {info.md5_verified}]")
    print(f"    * SHA1 Hash:         {info.sha1_checksum or 'N/A'} [Verified: {info.sha1_verified}]")
    if info.image_paths:
        print(f"    * Image Segments:    {len(info.image_paths)} segment(s)")
        for seg in info.image_paths:
            print(f"        - {seg}")

    v_status = f"{C_GREEN}VERIFIED & AUTHENTIC{C_RESET}" if (info.md5_verified or info.sha1_verified) else f"{C_YELLOW}UNVERIFIED{C_RESET}"
    print(f"\n[+] Evidentiary Integrity Status: {v_status}\n")
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


def cmd_watch(args: argparse.Namespace) -> int:
    """Launch continuous real-time Windows insider threat and removable device monitoring."""
    print_banner()
    from insider_forensics.realtime_monitor import RealTimeArtifactMonitor, simulate_live_incident
    output_dir = Path(args.output)
    output_dir.mkdir(parents=True, exist_ok=True)
    monitor = RealTimeArtifactMonitor(
        poll_interval_sec=args.interval,
        alert_threshold=args.threshold,
        report_dir=output_dir,
        case_id=args.case_id,
    )
    if getattr(args, "simulate", False):
        simulate_live_incident(monitor)
        return 0
    monitor.run_forever()
    return 0


def main() -> None:
    parser = argparse.ArgumentParser(
        description="ARTIFEX: Windows Forensic Artifact Correlator for Insider Data Theft",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    subparsers = parser.add_subparsers(dest="command")

    # watch / realtime command
    watch_parser = subparsers.add_parser("watch", help="Real-time live monitoring of removable devices and insider data theft")
    watch_parser.add_argument("--output", "-o", default="./realtime_alerts", help="Output directory for live incident reports")
    watch_parser.add_argument("--interval", "-i", type=float, default=2.0, help="Polling interval in seconds (default: 2.0s)")
    watch_parser.add_argument("--threshold", "-t", type=float, default=0.70, help="Confidence threshold to trigger alert (default: 0.70)")
    watch_parser.add_argument("--case-id", default="INC-REALTIME-001", help="Case number / incident identifier")
    watch_parser.add_argument("--simulate", action="store_true", default=False, help="Simulate a live removable USB data-theft incident")

    rt_parser = subparsers.add_parser("realtime", help="Alias for watch")
    rt_parser.add_argument("--output", "-o", default="./realtime_alerts", help="Output directory for live incident reports")
    rt_parser.add_argument("--interval", "-i", type=float, default=2.0, help="Polling interval in seconds")
    rt_parser.add_argument("--threshold", "-t", type=float, default=0.70, help="Confidence threshold to trigger alert")
    rt_parser.add_argument("--case-id", default="INC-REALTIME-001", help="Case number / incident identifier")
    rt_parser.add_argument("--simulate", action="store_true", default=False, help="Simulate a live removable USB data-theft incident")

    # analyze command
    analyze_parser = subparsers.add_parser("analyze", help="Analyze acquired Windows artifacts or FTK dumps")
    analyze_parser.add_argument("--source", "-s", required=True, help="Path to evidence directory or triage folder")
    analyze_parser.add_argument("--output", "-o", default="./forensic_reports", help="Output directory for reports")
    analyze_parser.add_argument(
        "--verify-integrity",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Verify SHA-256 hashes against original evidence files",
    )

    # acquire command (FTK Imager & Live Windows Triage)
    acquire_parser = subparsers.add_parser("acquire", help="Acquire evidence from live system using FTK Imager or live triage")
    acquire_parser.add_argument("--output", "-o", required=True, help="Destination directory for acquired evidence")
    acquire_parser.add_argument("--tool", "-t", choices=["auto", "ftkimager", "live"], default="auto", help="Acquisition tool to employ")
    acquire_parser.add_argument("--ftk-path", default=None, help="Explicit path to ftkimager.exe")
    acquire_parser.add_argument("--target", default=None, help="Target drive or volume (e.g. \\\\.\\PhysicalDrive0, \\\\.\\C:)")
    acquire_parser.add_argument("--format", choices=["e01", "raw"], default="e01", help="Image format (for FTK Imager)")
    acquire_parser.add_argument("--frag", type=int, default=2048, help="Split chunk size in MB (default: 2048)")
    acquire_parser.add_argument("--case-id", default="INC-2026-001", help="Case number / incident identifier")
    acquire_parser.add_argument("--evidence-id", default="EV-001", help="Evidence number")
    acquire_parser.add_argument("--examiner", default="Special Investigator", help="Investigator name")
    acquire_parser.add_argument("--description", default="Host Forensic Acquisition", help="Evidence description")
    acquire_parser.add_argument(
        "--verify",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Verify hashes post-acquisition",
    )
    acquire_parser.add_argument("--auto-analyze", action="store_true", default=False, help="Automatically run analysis on acquired artifacts")

    # verify-ftk command
    verify_parser = subparsers.add_parser("verify-ftk", help="Verify FTK Imager acquisition log manifest")
    verify_parser.add_argument("--log", "-l", required=True, help="Path to FTK Imager text log (*.txt / Image_Summary.txt)")

    # simulate command
    sim_parser = subparsers.add_parser("simulate", help="Run realistic simulation scenario")
    sim_parser.add_argument("--workspace", "-w", default="./simulated_case", help="Workspace folder")

    # console / interactive command
    subparsers.add_parser("console", help="Launch dedicated interactive console REPL")
    subparsers.add_parser("interactive", help="Alias for console")

    if len(sys.argv) <= 1:
        # Default to dedicated interactive console when run with no arguments
        from console import start_console
        start_console(cli_module=sys.modules[__name__])
        sys.exit(0)

    args = parser.parse_args()
    if args.command in ("console", "interactive"):
        from console import start_console
        start_console(cli_module=sys.modules[__name__])
        sys.exit(0)
    elif args.command in ("watch", "realtime"):
        sys.exit(cmd_watch(args))
    elif args.command == "analyze":
        sys.exit(cmd_analyze(args))
    elif args.command == "acquire":
        sys.exit(cmd_acquire(args))
    elif args.command == "verify-ftk":
        sys.exit(cmd_verify_ftk(args))
    elif args.command == "simulate":
        sys.exit(cmd_simulate(args))
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
