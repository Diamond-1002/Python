"""
==============================================================================
  restore.py  —  Standalone Folder Restore Utility
  Proactive Honeypot-Driven Ransomware Defence Framework
==============================================================================
  Algorithm 6: RESTORE_FOLDER_ACCESS(PROTECTED_DIRS)

  Run this script AFTER you have:
    1. Confirmed (e.g., via Task Manager / antivirus) the suspicious
       process is not ransomware — OR — terminated it yourself.
    2. Decided to re-enable normal write access to your folders.

  Usage
  -----
    python restore.py                          # restore dirs in config.json
    python restore.py --config my_config.json  # custom config
    python restore.py --force                  # skip confirmation prompt

  What it does
  ------------
    • Reads the same config.json as the main framework.
    • Strips all DENY ACEs from every directory in the config.
    • Applies a clean ALLOW ACE (current user + SYSTEM — full access).
    • Prints a confirmation for each directory restored.
    • Does NOT restart the monitor — run main.py again for that.
==============================================================================
"""

import sys
import os
import argparse
import json
import logging
from pathlib import Path

sys.path.insert(0, os.path.dirname(__file__))

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)8s] %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)
log = logging.getLogger("Restore")

# ── Try to import win32security ────────────────────────────────────────────────
WIN32_AVAILABLE = False
try:
    import win32api, win32con, win32security, ntsecuritycon, pywintypes
    WIN32_AVAILABLE = True
except ImportError:
    log.warning("pywin32 not found — ACL restoration will be simulated.")


def load_config(path: str) -> dict:
    try:
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)
    except FileNotFoundError:
        home = Path.home()
        return {
            "directories": [
                str(home / "Desktop"),
                str(home / "Documents"),
                str(home / "Downloads"),
            ]
        }


def restore_directory(directory: str):
    """
    Algorithm 6, lines 2-5:
      ACL ← GetFileSecurity(dir, DACL_SECURITY_INFORMATION)
      REMOVE_DENY_ACES(ACL)
      SetFileSecurity(dir, DACL_SECURITY_INFORMATION, ACL)
    """
    if not WIN32_AVAILABLE:
        log.info(f"[SIM] Restore simulated for: {directory}")
        return

    try:
        # ── Step 1: Build a fresh permissive DACL ─────────────────────────
        clean_dacl = win32security.ACL()

        # ALLOW SYSTEM — full access
        system_sid = win32security.CreateWellKnownSid(
            win32security.WinLocalSystemSid, None
        )
        clean_dacl.AddAccessAllowedAceEx(
            win32security.ACL_REVISION_DS,
            win32security.CONTAINER_INHERIT_ACE | win32security.OBJECT_INHERIT_ACE,
            ntsecuritycon.FILE_ALL_ACCESS,
            system_sid,
        )

        # ALLOW current user — full access
        token    = win32security.OpenProcessToken(
            win32api.GetCurrentProcess(),
            win32security.TOKEN_QUERY,
        )
        user_sid = win32security.GetTokenInformation(
            token, win32security.TokenUser
        )[0]
        clean_dacl.AddAccessAllowedAceEx(
            win32security.ACL_REVISION_DS,
            win32security.CONTAINER_INHERIT_ACE | win32security.OBJECT_INHERIT_ACE,
            ntsecuritycon.FILE_ALL_ACCESS,
            user_sid,
        )

        # ALLOW Administrators group — full access
        admins_sid = win32security.CreateWellKnownSid(
            win32security.WinBuiltinAdministratorsSid, None
        )
        clean_dacl.AddAccessAllowedAceEx(
            win32security.ACL_REVISION_DS,
            win32security.CONTAINER_INHERIT_ACE | win32security.OBJECT_INHERIT_ACE,
            ntsecuritycon.FILE_ALL_ACCESS,
            admins_sid,
        )

        # ── Step 2: Apply ─────────────────────────────────────────────────
        sd = win32security.SECURITY_DESCRIPTOR()
        sd.SetSecurityDescriptorDacl(True, clean_dacl, False)

        win32security.SetFileSecurity(
            directory,
            win32security.DACL_SECURITY_INFORMATION,
            sd,
        )
        log.info(f"[RESTORE] ✓  {directory}  →  Normal access restored")

    except pywintypes.error as exc:
        log.error(f"[ERROR] SetFileSecurity failed for {directory}: {exc}")
        log.error("        You may need to run this script as Administrator.")
    except Exception as exc:
        log.error(f"[ERROR] Unexpected error for {directory}: {exc}")


def confirm_restore(directories: list[str]) -> bool:
    print("\n" + "=" * 60)
    print("  FOLDER RESTORE UTILITY")
    print("=" * 60)
    print("  Directories to restore:")
    for d in directories:
        print(f"    •  {d}")
    print("=" * 60)
    print("  ⚠️  Restoring access means the ransomware (if still running)")
    print("      may be able to encrypt files again.")
    print("  Only proceed if you have neutralised the threat.\n")
    ans = input("  Type YES to confirm restore: ").strip().upper()
    return ans == "YES"


def run_restore(config_path: str, force: bool = False):
    cfg         = load_config(config_path)
    directories = cfg.get("directories", [])

    if not directories:
        log.error("No directories found in config — nothing to restore.")
        return

    if not force:
        if not confirm_restore(directories):
            print("\n[ABORT] Restore cancelled.")
            return

    print()
    for d in directories:
        restore_directory(d)

    # Algorithm 6, line 7
    print()
    log.info("[RESTORE] All done. Run 'python main.py' to restart monitoring.")

    if WIN32_AVAILABLE:
        try:
            win32api.MessageBox(
                0,
                "All protected directories have been restored to normal access.\n\n"
                "Run main.py again to restart ransomware monitoring.",
                "Access Restored",
                win32con.MB_OK | win32con.MB_ICONINFORMATION,
            )
        except Exception:
            pass


# ─── Entry point ─────────────────────────────────────────────────────────────

def main():
    p = argparse.ArgumentParser(
        description="Restore folder ACLs locked by the Honeypot Defence Framework."
    )
    p.add_argument("--config", default="config.json",
                   help="Path to config.json (default: config.json)")
    p.add_argument("--force", action="store_true",
                   help="Skip confirmation prompt")
    args = p.parse_args()
    run_restore(args.config, force=args.force)


if __name__ == "__main__":
    main()
