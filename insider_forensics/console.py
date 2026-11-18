"""Interactive Forensic Console REPL for ARTIFEX.

Provides a dedicated interactive command-line environment with auto-completion,
history, and direct access to all ARTIFEX analysis, simulation, acquisition,
and verification capabilities without retyping 'python3 ...'.
"""

from __future__ import annotations

import cmd
import os
import re
import shlex
import sys
from pathlib import Path
from typing import List, Optional

# Readline for command history and tab completion
try:
    import readline
except ImportError:
    readline = None

# ANSI color codes
C_CYAN = "\033[96m"
C_GREEN = "\033[92m"
C_YELLOW = "\033[93m"
C_RED = "\033[91m"
C_WHITE = "\033[97m"
C_BOLD = "\033[1m"
C_DIM = "\033[90m"
C_RESET = "\033[0m"

HISTORY_FILE = Path.home() / ".artifex_history"


def split_cmd_args(arg: str) -> List[str]:
    """Split command arguments preserving Windows backslashes and quoted paths with spaces.

    Handles:
    - Windows backslashes (e.g. C:\\Cases\\TestRun) without treating \\ as an escape character.
    - Quoted paths containing spaces (e.g. "C:\\My Cases\\Folder").
    - Accidental spaces in flags (e.g. '-- source' -> '--source').
    """
    if not arg or not arg.strip():
        return []

    # Normalize flag spaces like '-- source' -> '--source'
    normalized = re.sub(r"--\s+([a-zA-Z0-9_\-]+)", r"--\1", arg.strip())

    try:
        # posix=False prevents stripping backslashes on Windows
        raw_tokens = shlex.split(normalized, posix=False)
        cleaned = []
        for token in raw_tokens:
            if (token.startswith('"') and token.endswith('"')) or (token.startswith("'") and token.endswith("'")):
                cleaned.append(token[1:-1])
            else:
                cleaned.append(token)
        return cleaned
    except Exception:
        return [t.strip("\"'") for t in normalized.split()]


class ArtifexConsole(cmd.Cmd):
    """Interactive shell for ARTIFEX Forensic Examination Engine."""

    intro = ""
    prompt = f"{C_BOLD}{C_CYAN}artifex{C_RESET}{C_BOLD}>{C_RESET} "

    def __init__(self, cli_module=None) -> None:
        super().__init__()
        self.cli = cli_module
        self._init_history()

    def _init_history(self) -> None:
        if readline is not None:
            try:
                readline.set_completer_delims(" \t\n`!@#$%^&*()=+[{]}\\|;:'\",<>?")
                if HISTORY_FILE.exists():
                    readline.read_history_file(str(HISTORY_FILE))
                readline.set_history_length(1000)
            except Exception:
                pass

    def _save_history(self) -> None:
        if readline is not None:
            try:
                readline.write_history_file(str(HISTORY_FILE))
            except Exception:
                pass

    def emptyline(self) -> bool:
        """Do nothing on empty line."""
        return False

    def default(self, line: str) -> bool:
        """Handle unknown commands or shell pass-through."""
        line = line.strip()
        if not line:
            return False
        if line.startswith("!"):
            # Shell command escape
            os.system(line[1:].strip())
            return False
        print(f"{C_RED}[!] Unknown command: '{line}'. Type 'help' or '?' for available commands.{C_RESET}")
        return False

    def _complete_path(self, text: str, line: str, begidx: int, endidx: int) -> List[str]:
        """Auto-complete file and directory paths."""
        try:
            line_parts = split_cmd_args(line[:begidx])
            prefix = text.strip("\"'")
        except Exception:
            prefix = text.strip("\"'")

        expanded = os.path.expanduser(prefix)
        dirname = os.path.dirname(expanded) or "."
        basename = os.path.basename(expanded)

        matches = []
        sep = "\\" if os.name == "nt" else "/"
        try:
            for entry in os.listdir(dirname):
                if entry.startswith(basename):
                    full_path = os.path.join(dirname, entry)
                    if os.path.isdir(full_path):
                        matches.append(entry + sep)
                    else:
                        matches.append(entry + " ")
        except Exception:
            pass
        return matches

    # ==========================
    # Command: simulate
    # ==========================
    def do_simulate(self, arg: str) -> None:
        """simulate [workspace_folder]
        Generate a synthetic insider data-theft incident scenario and run full pipeline analysis.
        Example:
            simulate
            simulate ./my_test_case
        """
        import argparse
        parts = split_cmd_args(arg)
        workspace = parts[0] if parts else "./simulated_case"
        args = argparse.Namespace(workspace=workspace)
        if self.cli:
            sim_dir = Path(args.workspace) / "synthetic_evidence"
            report_dir = Path(args.workspace) / "reports"
            print(f"[*] Generating test scenario into: {sim_dir}")
            from insider_forensics.test_suite.generator import generate_synthetic_scenario
            generate_synthetic_scenario(sim_dir)

            sub_args = argparse.Namespace(
                source=str(sim_dir),
                output=str(report_dir),
                verify_integrity=True,
            )
            self.cli.cmd_analyze(sub_args, show_banner=False)

    def complete_simulate(self, text: str, line: str, begidx: int, endidx: int) -> List[str]:
        return self._complete_path(text, line, begidx, endidx)

    # ==========================
    # Command: analyze
    # ==========================
    def do_analyze(self, arg: str) -> None:
        """analyze --source <path> [--output <path>] [--no-verify-integrity]
        or shortcut:
        analyze <source_path> [<output_path>]

        Analyze acquired Windows forensic artifacts, EVTX, Registry, Prefetch, LNK, etc.
        Example:
            analyze simulated_case/synthetic_evidence
            analyze C:\\Cases\\TestRun\\Parsed\\FileFolderAccess
            analyze --source "C:\\Cases\\TestRun\\Parsed\\FileFolderAccess" --output "C:\\Reports"
        """
        import argparse
        try:
            parts = split_cmd_args(arg)
        except Exception as e:
            print(f"{C_RED}[!] Parsing error: {e}{C_RESET}")
            return

        if not parts:
            print(f"{C_YELLOW}Usage: analyze <source_dir> [output_dir] OR analyze --source <path> [--output <path>]{C_RESET}")
            return

        # Check if user used standard positional shortcut: analyze <src> [<dst>]
        if not parts[0].startswith("-"):
            source = parts[0]
            output = parts[1] if len(parts) > 1 else "./forensic_reports"
            args = argparse.Namespace(source=source, output=output, verify_integrity=True)
        else:
            parser = argparse.ArgumentParser(prog="analyze")
            parser.add_argument("--source", "-s", required=True)
            parser.add_argument("--output", "-o", default="./forensic_reports")
            parser.add_argument("--verify-integrity", action=argparse.BooleanOptionalAction, default=True)
            try:
                args = parser.parse_args(parts)
            except SystemExit:
                return

        if self.cli:
            self.cli.cmd_analyze(args, show_banner=False)

    def complete_analyze(self, text: str, line: str, begidx: int, endidx: int) -> List[str]:
        return self._complete_path(text, line, begidx, endidx)

    # ==========================
    # Command: verify_ftk / verify-ftk
    # ==========================
    def do_verify_ftk(self, arg: str) -> None:
        """verify_ftk <log_path> (or verify-ftk <log_path>)
        Parse and verify an AccessData / Exterro FTK Imager acquisition log manifest.
        Example:
            verify_ftk test_suite/sample_ftk_summary.txt
        """
        import argparse
        parts = split_cmd_args(arg)
        if not parts:
            print(f"{C_YELLOW}Usage: verify_ftk <path_to_ftk_log.txt>{C_RESET}")
            return

        log_path = parts[0] if not parts[0].startswith("-") else (parts[1] if len(parts) > 1 else "")
        if not log_path:
            print(f"{C_YELLOW}Usage: verify_ftk <path_to_ftk_log.txt>{C_RESET}")
            return

        args = argparse.Namespace(log=log_path)
        if self.cli:
            self.cli.cmd_verify_ftk(args)

    def complete_verify_ftk(self, text: str, line: str, begidx: int, endidx: int) -> List[str]:
        return self._complete_path(text, line, begidx, endidx)

    # Alias with hyphen
    do_verify = do_verify_ftk
    complete_verify = complete_verify_ftk

    # ==========================
    # Command: acquire
    # ==========================
    def do_acquire(self, arg: str) -> None:
        """acquire --output <dir> [--tool auto|ftkimager|live] [--case-id <id>] [--auto-analyze]
        or shortcut:
        acquire <output_dir>

        Acquire forensic artifacts from live endpoint via FTK Imager CLI or Live Triage Collector.
        Example:
            acquire ./live_case_01
            acquire --output ./live_case --tool live --case-id INC-99 --auto-analyze
        """
        import argparse
        try:
            parts = split_cmd_args(arg)
        except Exception as e:
            print(f"{C_RED}[!] Parsing error: {e}{C_RESET}")
            return

        if not parts:
            print(f"{C_YELLOW}Usage: acquire <output_dir> OR acquire --output <path> [options]{C_RESET}")
            return

        if not parts[0].startswith("-"):
            output = parts[0]
            args = argparse.Namespace(
                output=output,
                tool="auto",
                ftk_path=None,
                target=None,
                format="e01",
                frag=2048,
                case_id="INC-2026-001",
                evidence_id="EV-001",
                examiner="Special Investigator",
                description="Host Forensic Acquisition",
                verify=True,
                auto_analyze=False,
            )
        else:
            parser = argparse.ArgumentParser(prog="acquire")
            parser.add_argument("--output", "-o", required=True)
            parser.add_argument("--tool", "-t", choices=["auto", "ftkimager", "live"], default="auto")
            parser.add_argument("--ftk-path", default=None)
            parser.add_argument("--target", default=None)
            parser.add_argument("--format", choices=["e01", "raw"], default="e01")
            parser.add_argument("--frag", type=int, default=2048)
            parser.add_argument("--case-id", default="INC-2026-001")
            parser.add_argument("--evidence-id", default="EV-001")
            parser.add_argument("--examiner", default="Special Investigator")
            parser.add_argument("--description", default="Host Forensic Acquisition")
            parser.add_argument("--verify", action=argparse.BooleanOptionalAction, default=True)
            parser.add_argument("--auto-analyze", action="store_true", default=False)
            try:
                args = parser.parse_args(parts)
            except SystemExit:
                return

        if self.cli:
            self.cli.cmd_acquire(args)

    def complete_acquire(self, text: str, line: str, begidx: int, endidx: int) -> List[str]:
        return self._complete_path(text, line, begidx, endidx)

    # ==========================
    # Command: test
    # ==========================
    def do_test(self, arg: str) -> None:
        """test [suite_name]
        Run ARTIFEX forensic verification unit test suites.
        Example:
            test
            test all
            test ftk
            test artifacts
        """
        import unittest
        suite_choice = arg.strip().lower() if arg else "all"

        print(f"[*] Running ARTIFEX Test Suite ({suite_choice})...")
        loader = unittest.TestLoader()
        suite = unittest.TestSuite()

        if suite_choice in ("all", "forensics"):
            try:
                from test_suite.test_forensics import TestInsiderForensics
            except ImportError:
                from insider_forensics.test_suite.test_forensics import TestInsiderForensics
            suite.addTests(loader.loadTestsFromTestCase(TestInsiderForensics))

        if suite_choice in ("all", "ftk"):
            try:
                from test_suite.test_ftk_imager import TestFtkImagerIntegration
            except ImportError:
                from insider_forensics.test_suite.test_ftk_imager import TestFtkImagerIntegration
            suite.addTests(loader.loadTestsFromTestCase(TestFtkImagerIntegration))

        if suite_choice in ("all", "artifacts", "parsers"):
            try:
                from test_suite.test_real_artifacts import TestRealBinaryArtifacts
            except ImportError:
                try:
                    from insider_forensics.test_suite.test_real_artifacts import TestRealBinaryArtifacts
                except ImportError:
                    from test_suite.test_real_artifacts import TestRealArtifactParsers as TestRealBinaryArtifacts
            suite.addTests(loader.loadTestsFromTestCase(TestRealBinaryArtifacts))

        if suite_choice in ("all", "realtime", "watch", "usb"):
            try:
                from test_suite.test_realtime_monitor import TestRealTimeMonitor
            except ImportError:
                from insider_forensics.test_suite.test_realtime_monitor import TestRealTimeMonitor
            suite.addTests(loader.loadTestsFromTestCase(TestRealTimeMonitor))

        runner = unittest.TextTestRunner(verbosity=2)
        runner.run(suite)

    def complete_test(self, text: str, line: str, begidx: int, endidx: int) -> List[str]:
        options = ["all", "forensics", "ftk", "artifacts", "realtime"]
        return [o for o in options if o.startswith(text.lower())]

    # ==========================
    # Command: report / view
    # ==========================
    def do_view(self, arg: str) -> None:
        """view <report_file>
        Preview a generated forensic report or markdown summary in the terminal.
        Example:
            view simulated_case/reports/FORENSIC_REPORT.md
        """
        path_str = arg.strip().strip("\"'")
        if not path_str:
            default_path = Path("simulated_case/reports/FORENSIC_REPORT.md")
            if default_path.exists():
                path_str = str(default_path)
            else:
                print(f"{C_YELLOW}Usage: view <path_to_report>{C_RESET}")
                return

        p = Path(path_str)
        if not p.exists():
            print(f"{C_RED}[!] File not found: {p}{C_RESET}")
            return

        try:
            content = p.read_text(encoding="utf-8", errors="replace")
            print(f"\n{C_BOLD}{C_CYAN}=== Preview: {p.name} ==={C_RESET}\n")
            print(content)
        except Exception as e:
            print(f"{C_RED}[!] Could not read file: {e}{C_RESET}")

    def complete_view(self, text: str, line: str, begidx: int, endidx: int) -> List[str]:
        return self._complete_path(text, line, begidx, endidx)

    # ==========================
    # System / Utility Commands
    # ==========================
    def do_clear(self, arg: str) -> None:
        """clear
        Clear the terminal screen and redisplay banner.
        """
        os.system("clear" if os.name != "nt" else "cls")
        if self.cli:
            self.cli.print_banner()

    def do_banner(self, arg: str) -> None:
        """banner
        Display ARTIFEX ASCII header and platform overview.
        """
        if self.cli:
            self.cli.print_banner()

    def do_status(self, arg: str) -> None:
        """status
        Check system status, Python runtime, paths, and FTK Imager availability.
        """
        from insider_forensics.imager.ftk_imager import FTKImagerController
        ctrl = FTKImagerController()
        ftk_found = ctrl.is_available()

        print(f"\n{C_BOLD}[+] ARTIFEX System Status:{C_RESET}")
        print(f"    * Working Directory: {os.getcwd()}")
        print(f"    * Python Runtime:    {sys.version.split()[0]} ({sys.executable})")
        print(f"    * Platform:          {sys.platform}")
        ftk_status = f"{C_GREEN}Available ({ctrl.executable_path}){C_RESET}" if ftk_found else f"{C_YELLOW}Not Found (Using Live Triage Fallback){C_RESET}"
        print(f"    * FTK Imager CLI:    {ftk_status}")
        sim_exists = Path("simulated_case/synthetic_evidence").exists()
        print(f"    * Simulated Case:    {C_GREEN}Ready{C_RESET}" if sim_exists else f"{C_DIM}Not yet generated (run 'simulate'){C_RESET}")
        print()

    def do_exit(self, arg: str) -> bool:
        """exit (or quit)
        Exit the ARTIFEX interactive console.
        """
        print(f"{C_CYAN}Exiting ARTIFEX console. Goodbye!{C_RESET}")
        self._save_history()
        return True

    def do_quit(self, arg: str) -> bool:
        """quit
        Exit the ARTIFEX interactive console.
        """
        return self.do_exit(arg)

    def do_EOF(self, arg: str) -> bool:
        """Handle Ctrl+D to gracefully exit."""
        print()
        return self.do_exit(arg)

    # ==========================
    # Command: watch / realtime / monitor
    # ==========================
    def do_watch(self, arg: str) -> None:
        """watch [--output <dir>] [--interval <sec>] [--threshold <0.0-1.0>] [--simulate]
        or shortcut:
        watch [output_dir]

        Launch real-time Windows removable device monitoring, event reconstruction, and live reporting.
        Example:
            watch
            watch ./my_alerts
            watch --output ./live_alerts --simulate
            watch --interval 3.0 --threshold 0.75
        """
        import argparse
        try:
            parts = split_cmd_args(arg)
        except Exception as e:
            print(f"{C_RED}[!] Parsing error: {e}{C_RESET}")
            return

        parser = argparse.ArgumentParser(prog="watch")
        parser.add_argument("--output", "-o", default="./realtime_alerts")
        parser.add_argument("--interval", "-i", type=float, default=2.0)
        parser.add_argument("--threshold", "-t", type=float, default=0.70)
        parser.add_argument("--case-id", default="INC-REALTIME-001")
        parser.add_argument("--simulate", action="store_true", default=False)

        if parts and not parts[0].startswith("-"):
            args = argparse.Namespace(
                output=parts[0],
                interval=2.0,
                threshold=0.70,
                case_id="INC-REALTIME-001",
                simulate=("--simulate" in parts),
            )
        else:
            try:
                args = parser.parse_args(parts)
            except SystemExit:
                return

        if self.cli:
            self.cli.cmd_watch(args)

    def complete_watch(self, text: str, line: str, begidx: int, endidx: int) -> List[str]:
        return self._complete_path(text, line, begidx, endidx)

    do_realtime = do_watch
    complete_realtime = complete_watch
    do_monitor = do_watch
    complete_monitor = complete_watch

    def do_help(self, arg: str) -> None:
        """List available commands or show detailed help on a specific command."""
        if arg:
            # Check if method exists
            norm = arg.replace("-", "_")
            func = getattr(self, f"do_{norm}", None)
            if func and func.__doc__:
                print(f"\n{C_BOLD}{func.__doc__.strip()}{C_RESET}\n")
                return
            super().do_help(arg)
            return

        print(f"""
{C_BOLD}{C_WHITE}ARTIFEX Dedicated Interactive Console Commands:{C_RESET}
{C_DIM}--------------------------------------------------------------------------{C_RESET}
  {C_CYAN}watch{C_RESET}    [output] [--simulate] Real-time removable device monitoring & incident reconstruction
  {C_CYAN}simulate{C_RESET} [workspace]           Generate synthetic insider data theft scenario & analyze
  {C_CYAN}analyze{C_RESET}  <source> [output]     Analyze evidence folder (EVTX, Registry, LNK, Prefetch)
  {C_CYAN}acquire{C_RESET}  <output> [options]    Live forensic acquisition (FTK Imager CLI / Live Triage)
  {C_CYAN}verify_ftk{C_RESET} <log_file>          Ingest and verify FTK Imager acquisition manifest
  {C_CYAN}test{C_RESET}     [all|ftk|forensics]   Run automated forensic unit verification suites
  {C_CYAN}view{C_RESET}     [report_file]         Read generated markdown forensic investigation report
  {C_CYAN}status{C_RESET}                         Inspect environment, runtime, and FTK Imager status
  {C_CYAN}clear{C_RESET}                          Clear screen
  {C_CYAN}exit{C_RESET} / {C_CYAN}quit{C_RESET}                    Exit interactive console
{C_DIM}--------------------------------------------------------------------------{C_RESET}
  {C_DIM}Tip: You can use TAB for auto-completing commands and file paths.{C_RESET}
  {C_DIM}Tip: Type '!<command>' to run any system shell command directly.{C_RESET}
""")


def start_console(cli_module=None) -> None:
    """Launch the interactive REPL."""
    if cli_module:
        cli_module.print_banner()
    console = ArtifexConsole(cli_module=cli_module)
    try:
        console.cmdloop()
    except KeyboardInterrupt:
        print(f"\n{C_CYAN}Session interrupted. Exiting ARTIFEX console.{C_RESET}")
        console._save_history()
