"""
==============================================================================
  main.py  —  CLI Entry Point
  Proactive Honeypot-Driven Ransomware Defence Framework
==============================================================================
  Usage
  -----
    python main.py                          # start with default config.json
    python main.py --config my_config.json  # custom config path
    python main.py --simulate               # simulate a honeypot trigger
    python main.py --restore                # restore locked folders
    python main.py --list-honeypots         # deploy and list honeypots (dry-run)
    python main.py --status                 # print platform/dependency info
==============================================================================
"""

import sys
import os
import argparse
import time

# ── Ensure framework.py is importable from the same directory ─────────────────
sys.path.insert(0, os.path.dirname(__file__))
from framework import HoneypotDefenceFramework, _banner


def cmd_start(args):
    """Start the full framework (blocking)."""
    fw = HoneypotDefenceFramework(config_path=args.config)
    fw.start()


def cmd_restore(args):
    """Restore locked folders without re-starting the monitor."""
    _banner()
    fw = HoneypotDefenceFramework(config_path=args.config)
    fw.restore()
    print("\n[DONE] All directories restored. Framework reset.")


def cmd_simulate(args):
    """
    Start the framework, wait 5 seconds, then touch a honeypot file
    to simulate ransomware activity — useful for demo / testing.
    """
    import threading, glob, logging

    _banner()
    fw = HoneypotDefenceFramework(config_path=args.config)

    # Start framework in a background thread so we can interact with it
    t = threading.Thread(target=fw.start, daemon=True)
    t.start()

    print("\n[SIM] Framework started. Waiting 5 seconds before simulating attack …\n")
    time.sleep(5)

    # Pick any deployed honeypot and touch it
    if fw.honeypots:
        target = next(iter(fw.honeypots))  # first honeypot in the set
        print(f"[SIM] Simulating ransomware touching honeypot: {target}")
        try:
            with open(target, "ab") as fh:
                fh.write(b"\xDE\xAD\xBE\xEF")    # append 4 bytes = modification event
        except Exception as e:
            print(f"[SIM] Could not touch file (may need admin rights): {e}")
    else:
        print("[SIM] No honeypots deployed — check config directories exist.")

    print("[SIM] Trigger sent. Waiting 10 s for response …")
    time.sleep(10)
    fw.stop()


def cmd_list_honeypots(args):
    """Deploy honeypots and print their paths (dry-run, then cleanup)."""
    from framework import HoneypotDeployer, FILE_TYPES
    import json

    _banner()
    try:
        with open(args.config) as fh:
            cfg = json.load(fh)
    except FileNotFoundError:
        from pathlib import Path
        home = Path.home()
        cfg  = {
            "directories": [str(home / "Desktop"), str(home / "Documents"),
                             str(home / "Downloads")],
            "decoy_count": 3,
            "file_types":  FILE_TYPES,
        }

    deployer = HoneypotDeployer()
    honeypots = deployer.deploy(
        cfg["directories"],
        cfg.get("decoy_count", 3),
        cfg.get("file_types", FILE_TYPES),
    )

    print(f"\n{'─'*60}")
    print(f"  Deployed {len(honeypots)} honeypots:")
    print(f"{'─'*60}")
    for p in sorted(honeypots):
        print(f"  {p}")
    print(f"{'─'*60}")

    print("\n[LIST] Cleaning up honeypots …")
    deployer.cleanup()
    print("[LIST] Done.")


def cmd_status(_args):
    """Print platform & dependency information."""
    _banner()
    import platform, importlib

    print("Platform Information")
    print("─" * 50)
    print(f"  OS        : {platform.system()} {platform.version()}")
    print(f"  Python    : {sys.version.split()[0]}")
    print(f"  Admin     : {_is_admin()}")
    print()
    print("Dependency Status")
    print("─" * 50)
    for pkg in ["win32api", "win32file", "win32security", "ntsecuritycon",
                "psutil", "pywintypes"]:
        ok = _check_import(pkg)
        print(f"  {'✓' if ok else '✗'}  {pkg}")
    print()
    if not _is_admin():
        print("⚠️  Some features (NtSuspendProcess, SetFileSecurity) require")
        print("   Administrator privileges.  Run as Admin for full functionality.\n")


def _is_admin() -> bool:
    """Return True if the process has administrator privileges."""
    try:
        import ctypes
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return os.geteuid() == 0 if hasattr(os, "geteuid") else False


def _check_import(name: str) -> bool:
    try:
        __import__(name)
        return True
    except ImportError:
        return False


# ─── Argument Parser ──────────────────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="honeypot_defense",
        description=(
            "Proactive Honeypot-Driven Ransomware Defence Framework\n"
            "OS Course Project | March 2025"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py                          Start with config.json
  python main.py --config lab.json        Start with custom config
  python main.py --simulate               Demo: auto-trigger a honeypot
  python main.py --restore                Restore locked folders
  python main.py --list-honeypots         Show deployed honeypot paths
  python main.py --status                 Check dependencies & privileges
        """,
    )
    p.add_argument(
        "--config", default="config.json", metavar="PATH",
        help="Path to JSON configuration file (default: config.json)",
    )
    p.add_argument(
        "--simulate", action="store_true",
        help="Start framework and simulate a ransomware honeypot trigger after 5 s",
    )
    p.add_argument(
        "--restore", action="store_true",
        help="Restore ACLs on locked folders (run after threat is cleared)",
    )
    p.add_argument(
        "--list-honeypots", action="store_true",
        help="Deploy honeypots, list paths, then clean up",
    )
    p.add_argument(
        "--status", action="store_true",
        help="Print platform info and dependency availability",
    )
    return p


# ─── Entry Point ─────────────────────────────────────────────────────────────

def main():
    parser = build_parser()
    args   = parser.parse_args()

    if args.status:
        cmd_status(args)
    elif args.restore:
        cmd_restore(args)
    elif args.simulate:
        cmd_simulate(args)
    elif args.list_honeypots:
        cmd_list_honeypots(args)
    else:
        cmd_start(args)


if __name__ == "__main__":
    main()
