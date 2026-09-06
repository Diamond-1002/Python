"""
==============================================================================
  Proactive Honeypot-Driven Ransomware Defence Framework
  framework.py  —  Core Implementation (All 4 Modules)
  ==============================================================================
  Course  : Operating Systems | March 2025
  Authors : Diamond Porwal (24101110539) | Bhupesh Bansal (2410110531)
            Raghavendra Singh Sani (2410110465)

  MODULES IMPLEMENTED:
    1. HoneypotDeployer        – Algorithm 2: DEPLOY_HONEYPOTS
    2. FilesystemMonitor       – Algorithm 3: FILESYSTEM_MONITOR
    3. ProcessIsolationEngine  – Algorithm 4: PROCESS_ISOLATION_ENGINE
    4. FolderLockdownManager   – Algorithm 5: FOLDER_LOCKDOWN_MANAGER
    5. HoneypotDefenceFramework– Algorithm 1: Master orchestrator

  WINDOWS APIS USED:
    - ReadDirectoryChangesW   (win32file)       → real-time fs events
    - NtSuspendProcess        (ntdll via ctypes) → freeze offending process
    - SetFileSecurity / ACL   (win32security)   → directory lockdown
    - MessageBox              (win32api)         → user alerts
==============================================================================
"""

# ─── Standard Library ──────────────────────────────────────────────────────────
import os
import sys
import time
import json
import random
import logging
import threading
import ctypes
import ctypes.wintypes
from pathlib import Path
from datetime import datetime

# ─── Windows API imports (pywin32) ─────────────────────────────────────────────
#     Install with:  pip install pywin32 psutil
WIN32_AVAILABLE = False
if sys.platform == "win32":
    try:
        import win32api
        import win32con
        import win32file
        import win32security
        import win32process
        import ntsecuritycon
        import pywintypes
        import psutil

        # Low-level DLL handles for ctypes calls
        _ntdll   = ctypes.WinDLL("ntdll")
        _kernel32 = ctypes.WinDLL("kernel32")
        WIN32_AVAILABLE = True
    except ImportError as _e:
        print(f"[WARN] pywin32 / psutil not found ({_e}).")
        print("       Running in SIMULATION mode — no actual Windows API calls.")


# ─── Constants ─────────────────────────────────────────────────────────────────

FILE_TYPES = [".docx", ".pdf", ".jpg", ".xlsx", ".txt", ".png", ".csv"]

# Attractive decoy names that ransomware prioritises
PRIORITY_NAMES = [
    "Important_Document",  "Backup_2024",       "Resume_Final",
    "Invoice_March",       "Tax_Return_2024",   "Secret_Keys",
    "Password_List",       "Project_Report",    "Company_Data",
    "Medical_Records",     "Bank_Statement",    "Salary_Slip",
]

# Processes that are never treated as hostile
DEFAULT_WHITELIST = [
    "explorer.exe",  "python.exe",  "python3.exe",  "pythonw.exe",
    "code.exe",      "winword.exe", "excel.exe",    "notepad.exe",
    "chrome.exe",    "msedge.exe",  "firefox.exe",  "powershell.exe",
    "cmd.exe",
]

# ReadDirectoryChangesW action codes → human labels
_ACTION_MAP = {
    1: "FILE_CREATED",
    2: "FILE_DELETED",
    3: "FILE_MODIFIED",
    4: "RENAMED_OLD_NAME",
    5: "RENAMED_NEW_NAME",
}

# ─── Shared logger (configured in HoneypotDefenceFramework.__init__) ──────────
log = logging.getLogger("HoneypotFramework")


# ==============================================================================
#  MODULE 1 — HONEYPOT DEPLOYER
#  Pseudocode: Algorithm 2 — DEPLOY_HONEYPOTS(D, decoy_count, file_types)
# ==============================================================================

class HoneypotDeployer:
    """
    Generates and places decoy files in high-priority directories.

    Design rationale (from Palisse et al., 2017):
      - Files in Desktop / Documents / Downloads are targeted *first*
        by most ransomware traversal algorithms.
      - Attractive names (Backup, Invoice, Password …) raise the
        probability that ransomware enumerates and touches them early.
      - Hidden attribute prevents false triggers by the user.

    Attributes
    ----------
    honeypots : set[str]
        Lower-cased absolute paths of all deployed decoy files.
        O(1) membership test used by the filesystem monitor.
    """

    def __init__(self):
        self.honeypots: set[str] = set()
        self._log = logging.getLogger("HoneypotDeployer")

    # ------------------------------------------------------------------
    # Algorithm 2, line 1-14
    # ------------------------------------------------------------------
    def deploy(self, directories: list[str], decoy_count: int = 3,
               file_types: list[str] | None = None) -> set[str]:
        """
        Create *decoy_count* honeypot files in each directory of *directories*.

        Parameters
        ----------
        directories  : target dirs  (D in the algorithm)
        decoy_count  : decoys per directory
        file_types   : extensions to use  (default: FILE_TYPES)

        Returns
        -------
        set[str] : H — set of all deployed honeypot paths (lower-cased)
        """
        if file_types is None:
            file_types = FILE_TYPES

        self.honeypots.clear()

        for directory in directories:
            dir_path = Path(directory)

            # Create directory if it does not exist (lab safety)
            dir_path.mkdir(parents=True, exist_ok=True)

            for _ in range(decoy_count):
                # Algorithm 2, lines 5-7 : build file path
                name = random.choice(PRIORITY_NAMES) + f"_{random.randint(1000, 9999)}"
                ext  = random.choice(file_types)
                filepath = dir_path / (name + ext)

                # Algorithm 2, line 8-9 : create decoy with realistic size
                self._write_decoy(filepath)

                # Algorithm 2, line 10 : set HIDDEN attribute (Windows only)
                if WIN32_AVAILABLE:
                    try:
                        win32api.SetFileAttributes(
                            str(filepath),
                            win32con.FILE_ATTRIBUTE_HIDDEN
                        )
                    except Exception as exc:
                        self._log.debug(f"SetFileAttributes failed: {exc}")

                # Algorithm 2, line 11-12
                self.honeypots.add(str(filepath).lower())
                self._log.info(f"[HONEYPOT] Deployed → {filepath}")

        self._log.info(
            f"[DEPLOY] Total honeypots: {len(self.honeypots)} "
            f"across {len(directories)} directories."
        )
        return self.honeypots

    def _write_decoy(self, filepath: Path):
        """
        Fill the decoy with a realistic mix of printable header bytes
        and random binary data so entropy-based detectors see a plausible file.
        Size range: 512 KB – 2 MB (matches real user documents).
        """
        size = random.randint(512 * 1024, 2 * 1024 * 1024)
        try:
            with open(filepath, "wb") as fh:
                header = (
                    f"[HONEYPOT DECOY — DO NOT OPEN]\n"
                    f"Path : {filepath}\n"
                    f"Created : {datetime.now().isoformat()}\n\n"
                ).encode()
                fh.write(header)
                fh.write(os.urandom(size - len(header)))   # random payload
        except OSError as exc:
            self._log.error(f"Cannot create decoy {filepath}: {exc}")

    def cleanup(self):
        """Remove every deployed honeypot file on framework shutdown."""
        for path_str in list(self.honeypots):
            try:
                p = Path(path_str)
                if WIN32_AVAILABLE:
                    # Strip HIDDEN flag so unlink works without errors
                    win32api.SetFileAttributes(str(p), win32con.FILE_ATTRIBUTE_NORMAL)
                p.unlink(missing_ok=True)
                self._log.info(f"[CLEANUP] Removed honeypot → {p}")
            except Exception as exc:
                self._log.warning(f"Cleanup failed for {path_str}: {exc}")
        self.honeypots.clear()

    def is_honeypot(self, filepath: str) -> bool:
        """O(1) membership check."""
        return filepath.lower() in self.honeypots


# ==============================================================================
#  MODULE 2 — FILESYSTEM MONITOR
#  Pseudocode: Algorithm 3 — FILESYSTEM_MONITOR(D, H)
# ==============================================================================

class FilesystemMonitor:
    """
    Watches all directories in D using Windows ReadDirectoryChangesW.

    One dedicated daemon thread is spawned per directory (Algorithm 3,
    lines 1-3).  Each thread blocks on ReadDirectoryChangesW and
    immediately calls the trigger callback on a honeypot match
    (Algorithm 3, lines 9-13).

    On non-Windows or without pywin32, a 500 ms polling fallback is used.
    """

    def __init__(self, honeypots: set[str], on_trigger):
        """
        Parameters
        ----------
        honeypots  : set H — lower-cased honeypot paths
        on_trigger : callable(filepath, action_str)  — callback for Modules 3 & 4
        """
        self.honeypots   = honeypots
        self.on_trigger  = on_trigger
        self._stop_event = threading.Event()
        self._threads: list[threading.Thread] = []
        self._log = logging.getLogger("FilesystemMonitor")

    # ------------------------------------------------------------------
    # Algorithm 3, lines 1-6 : open handles and launch threads
    # ------------------------------------------------------------------
    def start(self, directories: list[str]):
        """Launch one high-priority monitor thread per directory."""
        for directory in directories:
            t = threading.Thread(
                target=self._monitor_win32 if WIN32_AVAILABLE
                       else self._monitor_poll,
                args=(directory,),
                daemon=True,
                name=f"WatchThread-{Path(directory).name}",
            )
            t.start()
            self._threads.append(t)
            self._log.info(f"[MONITOR] Watching → {directory}")

    def stop(self):
        """Signal all monitor threads to terminate."""
        self._stop_event.set()

    # ------------------------------------------------------------------
    # Algorithm 3, lines 4-19 : Windows ReadDirectoryChangesW loop
    # ------------------------------------------------------------------
    def _monitor_win32(self, directory: str):
        """
        Primary monitor loop using ReadDirectoryChangesW.

        Win32 flags used:
          FILE_NOTIFY_CHANGE_FILE_NAME  — rename / delete / create
          FILE_NOTIFY_CHANGE_LAST_WRITE — content modification
          FILE_NOTIFY_CHANGE_SIZE       — size change (encryption enlarges files)
          FILE_NOTIFY_CHANGE_CREATION   — new file created
        """
        # Algorithm 3, line 2 : CreateFile on the directory
        try:
            h_dir = win32file.CreateFile(
                directory,
                win32con.GENERIC_READ,
                win32con.FILE_SHARE_READ | win32con.FILE_SHARE_WRITE | win32con.FILE_SHARE_DELETE,
                None,
                win32con.OPEN_EXISTING,
                win32con.FILE_FLAG_BACKUP_SEMANTICS,
                None,
            )
        except pywintypes.error as exc:
            self._log.error(f"Cannot open handle for {directory}: {exc}")
            return

        # Boost thread priority (WATCHDOG_THREAD — Algorithm 1, line 4)
        try:
            win32process.SetThreadPriority(
                win32api.GetCurrentThread(),
                win32process.THREAD_PRIORITY_ABOVE_NORMAL,
            )
        except Exception:
            pass

        self._log.info(f"[MONITOR] Win32 handle opened for: {directory}")

        # Algorithm 3, line 4 : LOOP
        while not self._stop_event.is_set():
            try:
                # Algorithm 3, line 6 : ReadDirectoryChangesW (blocking)
                results = win32file.ReadDirectoryChangesW(
                    h_dir,
                    65536,   # buffer size (bytes)
                    True,    # recursive — watch all subdirectories
                    (win32con.FILE_NOTIFY_CHANGE_FILE_NAME |
                     win32con.FILE_NOTIFY_CHANGE_LAST_WRITE |
                     win32con.FILE_NOTIFY_CHANGE_SIZE |
                     0x00000040),          # FILE_NOTIFY_CHANGE_CREATION (raw value — win32con omits this)
                    None,    # overlapped structure (synchronous mode)
                    None,    # completion routine
                )

                # Algorithm 3, lines 7-14 : process each event
                for action_code, filename in results:
                    full_path = os.path.join(directory, filename)
                    self._dispatch(full_path, action_code)

            except pywintypes.error as exc:
                if not self._stop_event.is_set():
                    self._log.error(f"ReadDirectoryChangesW error: {exc}")
                break

        # Algorithm 3, line 19 : close handle
        try:
            win32file.CloseHandle(h_dir)
        except Exception:
            pass

    def _monitor_poll(self, directory: str):
        """
        Fallback: poll every 500 ms for mtime changes.
        Used when pywin32 is unavailable (dev / CI environments).
        """
        self._log.warning(f"[MONITOR] Polling fallback for: {directory}")
        snapshot: dict[str, float] = {}

        while not self._stop_event.is_set():
            try:
                for root, _, files in os.walk(directory):
                    for fname in files:
                        fpath = os.path.join(root, fname)
                        try:
                            mtime = os.path.getmtime(fpath)
                        except OSError:
                            continue
                        prev  = snapshot.get(fpath)
                        if prev is None:
                            snapshot[fpath] = mtime          # first sight → FILE_CREATED
                            self._dispatch(fpath, 1)
                        elif prev != mtime:
                            snapshot[fpath] = mtime          # changed     → FILE_MODIFIED
                            self._dispatch(fpath, 3)
            except Exception as exc:
                self._log.error(f"Poll error: {exc}")
            time.sleep(0.5)

    # ------------------------------------------------------------------
    # Algorithm 3, lines 8-13 : check honeypot membership → trigger
    # ------------------------------------------------------------------
    def _dispatch(self, full_path: str, action_code: int):
        """
        O(1) set lookup.  If path ∈ H  →  invoke the trigger callback.
        """
        action_str = _ACTION_MAP.get(action_code, f"ACTION_{action_code}")
        self._log.debug(f"[EVENT] {action_str} → {full_path}")

        if full_path.lower() in self.honeypots:
            self._log.warning(
                f"[!!!] HONEYPOT TRIGGERED | {action_str} | {full_path}"
            )
            # Algorithm 3, lines 11-13
            self.on_trigger(full_path, action_str)


# ==============================================================================
#  MODULE 3 — PROCESS IDENTIFICATION & ISOLATION ENGINE
#  Pseudocode: Algorithm 4 — PROCESS_ISOLATION_ENGINE(pid)
# ==============================================================================

class ProcessIsolationEngine:
    """
    Identifies and suspends (or terminates) the offending process.

    PID Resolution
    --------------
    ReadDirectoryChangesW does not expose the PID in its event record.
    The pseudocode calls GET_PID_FROM_EVENT which maps to
    NtQuerySystemInformation(SystemHandleInformation) — iterate all
    open handles system-wide and find which process has the honeypot
    file open.

    In this implementation we use psutil.Process.open_files() which
    wraps the same kernel query in a safe Python API.  For academic
    correctness the ctypes-level NtQuerySystemInformation approach is
    documented in the comments below.

    Suspension
    ----------
    NtSuspendProcess is an undocumented but stable ntdll export that
    suspends ALL threads of a process atomically (unlike the documented
    SuspendThread which requires iterating threads).
    """

    def __init__(self, whitelist: list[str] | None = None):
        self.whitelist       = [w.lower() for w in (whitelist or DEFAULT_WHITELIST)]
        self.suspended_pids: list[int] = []
        self._log = logging.getLogger("ProcessIsolation")

    # ------------------------------------------------------------------
    # Algorithm 4, lines 1-21
    # ------------------------------------------------------------------
    def isolate(self, triggered_filepath: str) -> int | None:
        """
        Full isolation routine for the process that touched the honeypot.

        Returns the PID that was suspended, or None.
        """
        self._log.info(f"[ISOLATE] Searching for process that touched: {triggered_filepath}")

        # Algorithm 4, lines 1-4 : NULL/zero PID guard
        pid = self._find_pid(triggered_filepath)
        if not pid:
            self._log.warning("[WARN] Could not resolve PID — applying lockdown only.")
            return None

        proc_name, proc_path = self._query_process_info(pid)

        # Algorithm 4, lines 8-11 : whitelist check
        if proc_name.lower() in self.whitelist:
            self._log.info(f"[WHITELIST] '{proc_name}' is whitelisted — no action taken.")
            return None

        self._log.warning(
            f"[ALERT] Offending process → PID={pid} | Name={proc_name} | Path={proc_path}"
        )

        # Algorithm 4, lines 12-20 : open handle + call NtSuspendProcess
        ok = self._nt_suspend(pid)
        if ok:
            self.suspended_pids.append(pid)
            self._log.warning(f"[SUSPENDED] PID {pid} ({proc_name}) suspended via NtSuspendProcess ✓")
            self._alert_user(pid, proc_name, proc_path)
        else:
            self._log.error(f"[ERROR] NtSuspendProcess failed for PID {pid}. Falling back to TerminateProcess.")
            self._terminate(pid)

        return pid

    # ------------------------------------------------------------------
    # PID resolution via psutil (wraps NtQuerySystemInformation)
    # ------------------------------------------------------------------
    def _find_pid(self, filepath: str) -> int | None:
        """
        Scan all running processes for an open handle to *filepath*.

        NtQuerySystemInformation approach (academic reference):
          NTSTATUS NtQuerySystemInformation(
              SystemHandleInformation,  // 0x10
              PSYSTEM_HANDLE_INFORMATION pInfo,
              ULONG Length, PULONG ReturnLength);
          Then NtDuplicateObject + NtQueryObject to get the file name
          for each handle.  psutil wraps this in process.open_files().
        """
        if not WIN32_AVAILABLE:
            self._log.warning("[SIM] PID resolution skipped (no pywin32).")
            return None

        try:
            target = filepath.lower()
            for proc in psutil.process_iter(["pid", "name", "open_files"]):
                try:
                    for f in proc.open_files():
                        if f.path.lower() == target:
                            self._log.info(
                                f"[PID FOUND] {proc.info['name']} (PID {proc.info['pid']}) "
                                f"has {filepath} open."
                            )
                            return proc.info["pid"]
                except (psutil.AccessDenied, psutil.NoSuchProcess, OSError):
                    continue
        except Exception as exc:
            self._log.error(f"PID enumeration error: {exc}")

        return None

    def _query_process_info(self, pid: int) -> tuple[str, str]:
        """Return (process_name, executable_path) for *pid*."""
        if WIN32_AVAILABLE:
            try:
                p = psutil.Process(pid)
                return p.name(), p.exe()
            except Exception:
                pass
        return f"PID_{pid}", "UNKNOWN"

    # ------------------------------------------------------------------
    # Algorithm 4, lines 12-13 : OpenProcess + NtSuspendProcess
    # ------------------------------------------------------------------
    def _nt_suspend(self, pid: int) -> bool:
        """
        Suspend all threads in the process atomically.

        Win32 sequence:
          1. OpenProcess(PROCESS_SUSPEND_RESUME, FALSE, pid) → hProcess
          2. NtSuspendProcess(hProcess)
             Returns NTSTATUS — 0 (STATUS_SUCCESS) means OK.
          3. CloseHandle(hProcess)
        """
        if not WIN32_AVAILABLE:
            self._log.info(f"[SIM] NtSuspendProcess({pid}) — simulated ✓")
            return True

        PROCESS_SUSPEND_RESUME = 0x0800

        # Algorithm 4, line 12
        h = _kernel32.OpenProcess(PROCESS_SUSPEND_RESUME, False, pid)
        if not h:
            err = ctypes.GetLastError()
            self._log.error(f"OpenProcess failed: Win32 error {err}")
            return False

        try:
            # Algorithm 4, line 13 — NtSuspendProcess is an ntdll export
            ntstatus = _ntdll.NtSuspendProcess(h)
            if ntstatus == 0:          # STATUS_SUCCESS
                return True
            self._log.error(f"NtSuspendProcess returned NTSTATUS 0x{ntstatus:08X}")
            return False
        finally:
            # Algorithm 4, line 21
            _kernel32.CloseHandle(h)

    def _terminate(self, pid: int):
        """Last-resort: TerminateProcess if NtSuspendProcess fails."""
        if not WIN32_AVAILABLE:
            self._log.info(f"[SIM] TerminateProcess({pid}) — simulated.")
            return
        PROCESS_TERMINATE = 0x0001
        h = _kernel32.OpenProcess(PROCESS_TERMINATE, False, pid)
        if h:
            _kernel32.TerminateProcess(h, 1)
            _kernel32.CloseHandle(h)
            self._log.warning(f"[TERMINATED] PID {pid} killed.")

    def _alert_user(self, pid: int, name: str, path: str):
        """Pop a Windows MessageBox (MB_SYSTEMMODAL so it appears on top)."""
        msg = (
            f"⚠️  RANSOMWARE DETECTED  ⚠️\n\n"
            f"Process  :  {name}\n"
            f"PID      :  {pid}\n"
            f"Location :  {path}\n\n"
            f"The process has been SUSPENDED.\n"
            f"Protected folders are now READ-ONLY.\n\n"
            f"Run  'python restore.py'  after confirming the threat is gone."
        )
        self._log.warning(msg)
        if WIN32_AVAILABLE:
            try:
                win32api.MessageBox(
                    0, msg, "⚠️  RANSOMWARE ALERT",
                    win32con.MB_OK | win32con.MB_ICONERROR | win32con.MB_SYSTEMMODAL,
                )
            except Exception:
                pass   # May fail if running as a service with no desktop


# ==============================================================================
#  MODULE 4 — FOLDER LOCKDOWN MANAGER
#  Pseudocode: Algorithm 5 — FOLDER_LOCKDOWN_MANAGER(PROTECTED_DIRS)
# ==============================================================================

class FolderLockdownManager:
    """
    Modifies NTFS ACLs to make protected directories read-only for
    all non-SYSTEM accounts.

    ACL order (critical — Windows evaluates ACEs top-to-bottom):
      1. DENY  Everyone  (FILE_WRITE | DELETE | WRITE_DAC)   ← explicit deny first
      2. ALLOW SYSTEM    (GENERIC_ALL)                        ← service account OK
      3. ALLOW current user (READ | EXECUTE)                  ← user can still read

    The original ACL is saved so RESTORE_FOLDER_ACCESS can reinstate it.
    """

    def __init__(self):
        self.locked_dirs: list[str]     = []
        self.original_sds: dict[str, object] = {}   # dir → original SECURITY_DESCRIPTOR
        self._log = logging.getLogger("FolderLockdown")

    # ------------------------------------------------------------------
    # Algorithm 5, lines 1-12
    # ------------------------------------------------------------------
    def lockdown(self, directories: list[str]):
        """Apply read-only ACLs to all directories in PROTECTED_DIRS."""
        self._log.warning("[LOCKDOWN] Applying ACL lockdown …")
        for d in directories:
            self._apply_lockdown(d)
        self._notify_lockdown(directories)

    def _apply_lockdown(self, directory: str):
        """
        Algorithm 5, lines 2-11 for a single directory.
        """
        if not WIN32_AVAILABLE:
            self._log.info(f"[SIM] ACL lockdown simulated for: {directory}")
            self.locked_dirs.append(directory)
            return

        try:
            # Algorithm 5, line 2 : GetFileSecurity → save original ACL
            sd_original = win32security.GetFileSecurity(
                directory,
                win32security.DACL_SECURITY_INFORMATION,
            )
            self.original_sds[directory] = sd_original

            # Algorithm 5, line 3 : CREATE_EMPTY_ACL
            new_dacl = win32security.ACL()

            # Algorithm 5, lines 4-5 : DENY Everyone write / delete
            everyone_sid = win32security.CreateWellKnownSid(
                win32security.WinWorldSid, None
            )
            deny_mask = (
                ntsecuritycon.FILE_GENERIC_WRITE   |   # write data
                win32con.FILE_DELETE_CHILD         |   # delete children
                win32con.DELETE                    |   # delete the dir itself
                win32con.WRITE_DAC                 |   # change permissions
                win32con.WRITE_OWNER               |   # take ownership
            0)
            new_dacl.AddAccessDeniedAceEx(
                win32security.ACL_REVISION_DS,
                win32security.CONTAINER_INHERIT_ACE | win32security.OBJECT_INHERIT_ACE,
                deny_mask,
                everyone_sid,
            )

            # Algorithm 5, lines 6-7 : ALLOW SYSTEM full access
            system_sid = win32security.CreateWellKnownSid(
                win32security.WinLocalSystemSid, None
            )
            new_dacl.AddAccessAllowedAceEx(
                win32security.ACL_REVISION_DS,
                win32security.CONTAINER_INHERIT_ACE | win32security.OBJECT_INHERIT_ACE,
                ntsecuritycon.FILE_ALL_ACCESS,
                system_sid,
            )

            # Extra: allow current user READ so they can browse files
            try:
                token  = win32security.OpenProcessToken(
                    win32api.GetCurrentProcess(),
                    win32security.TOKEN_QUERY,
                )
                user_sid = win32security.GetTokenInformation(
                    token, win32security.TokenUser
                )[0]
                new_dacl.AddAccessAllowedAceEx(
                    win32security.ACL_REVISION_DS,
                    win32security.CONTAINER_INHERIT_ACE | win32security.OBJECT_INHERIT_ACE,
                    ntsecuritycon.FILE_GENERIC_READ | ntsecuritycon.FILE_GENERIC_EXECUTE,
                    user_sid,
                )
            except Exception:
                pass   # Non-critical — SYSTEM access is the important part

            # Algorithm 5, lines 8-10 : SetFileSecurity with new DACL
            new_sd = win32security.SECURITY_DESCRIPTOR()
            new_sd.SetSecurityDescriptorDacl(True, new_dacl, False)
            win32security.SetFileSecurity(
                directory,
                win32security.DACL_SECURITY_INFORMATION,
                new_sd,
            )

            self.locked_dirs.append(directory)
            # Algorithm 5, line 11
            self._log.warning(f"[LOCKDOWN] ✓  {directory}  →  Read-Only (ACL enforced)")

        except Exception as exc:
            self._log.error(f"[ERROR] ACL lockdown failed for {directory}: {exc}")

    # ------------------------------------------------------------------
    # Algorithm 6 — RESTORE_FOLDER_ACCESS
    # ------------------------------------------------------------------
    def restore_all(self):
        """
        Strip deny ACEs and reinstate original security descriptors.
        Called by restore.py after the user confirms threat is clear.
        """
        self._log.info("[RESTORE] Restoring original ACLs …")
        for directory, original_sd in list(self.original_sds.items()):
            try:
                if WIN32_AVAILABLE:
                    win32security.SetFileSecurity(
                        directory,
                        win32security.DACL_SECURITY_INFORMATION,
                        original_sd,
                    )
                self._log.info(f"[RESTORE] ✓  {directory}  →  Normal access")
            except Exception as exc:
                self._log.error(f"[RESTORE ERROR] {directory}: {exc}")

        self.locked_dirs.clear()
        self.original_sds.clear()

        if WIN32_AVAILABLE:
            try:
                win32api.MessageBox(
                    0, "All directories restored to normal access.",
                    "Access Restored", win32con.MB_OK | win32con.MB_ICONINFORMATION,
                )
            except Exception:
                pass

    def _notify_lockdown(self, directories: list[str]):
        msg = (
            "🔒  FOLDER LOCKDOWN ACTIVE  🔒\n\n"
            "The following directories are now READ-ONLY:\n"
            + "\n".join(f"  •  {d}" for d in directories)
            + "\n\nRun  'python restore.py'  once the threat is confirmed clear."
        )
        self._log.warning(msg)
        if WIN32_AVAILABLE:
            try:
                win32api.MessageBox(
                    0, msg, "LOCKDOWN ACTIVE",
                    win32con.MB_OK | win32con.MB_ICONWARNING | win32con.MB_SYSTEMMODAL,
                )
            except Exception:
                pass


# ==============================================================================
#  MASTER ORCHESTRATOR
#  Pseudocode: Algorithm 1 — HONEYPOT_DEFENCE_FRAMEWORK_INIT()
# ==============================================================================

class HoneypotDefenceFramework:
    """
    Top-level controller.  Wires together all four modules and manages
    the run-loop, trigger response, and clean shutdown.

    Usage
    -----
    >>> fw = HoneypotDefenceFramework("config.json")
    >>> fw.start()          # blocks until Ctrl-C
    """

    def __init__(self, config_path: str = "config.json"):
        self._setup_logging()
        self.config   = self._load_config(config_path)
        self.honeypots: set[str] = set()
        self._triggered = False           # guard against duplicate responses
        self._lock      = threading.Lock()

        # Instantiate the four modules
        self.deployer   = HoneypotDeployer()
        self.monitor    = None            # created in start()
        self.isolator   = ProcessIsolationEngine(
            whitelist=self.config.get("whitelist", DEFAULT_WHITELIST)
        )
        self.lockdown   = FolderLockdownManager()

    # ------------------------------------------------------------------
    # Algorithm 1, lines 1-10
    # ------------------------------------------------------------------
    def start(self):
        """
        Initialise all modules, launch the watchdog thread, then block.
        """
        dirs        = self.config["directories"]
        decoy_count = self.config.get("decoy_count", 3)
        file_types  = self.config.get("file_types", FILE_TYPES)

        _banner()

        # Algorithm 1, line 2 : H ← DEPLOY_HONEYPOTS(D, n, types)
        log.info(f"[INIT] Deploying honeypots into {len(dirs)} directories …")
        self.honeypots = self.deployer.deploy(dirs, decoy_count, file_types)

        # Algorithm 1, lines 3-6 : create & start WATCHDOG_THREAD
        self.monitor = FilesystemMonitor(
            honeypots=self.honeypots,
            on_trigger=self._on_honeypot_triggered,
        )
        self.monitor.start(dirs)

        log.info(
            f"[READY] Framework active — {len(self.honeypots)} honeypots, "
            f"{len(dirs)} directories monitored."
        )
        log.info("[READY] Press Ctrl-C to stop.\n")

        # Algorithm 1, line 8 : WAIT_FOR_TERMINATION_SIGNAL
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            log.info("\n[STOP] Ctrl-C received — shutting down …")

        # Algorithm 1, line 9 : CLEANUP
        self.stop()

    def _on_honeypot_triggered(self, filepath: str, action: str):
        """
        Callback invoked by the filesystem monitor on a honeypot match.
        Runs in the watchdog thread; protected by a lock so only the
        first event fires modules 3 & 4.
        """
        with self._lock:
            if self._triggered:
                return                    # already responding — ignore duplicates
            self._triggered = True

        log.warning("=" * 62)
        log.warning("   ⚠️   RANSOMWARE ACTIVITY DETECTED — RESPONDING NOW   ⚠️")
        log.warning(f"   File   : {filepath}")
        log.warning(f"   Action : {action}")
        log.warning("=" * 62)

        # Algorithm 3, line 12 : CALL PROCESS_ISOLATION_ENGINE(pid)
        self.isolator.isolate(filepath)

        # Algorithm 3, line 13 : CALL FOLDER_LOCKDOWN_MANAGER(PROTECTED_DIRS)
        self.lockdown.lockdown(self.config["directories"])

        log.warning("[CONTAINED] Threat response complete. Awaiting user authorisation.")

    def stop(self):
        """Clean shutdown: stop monitor and remove honeypot files."""
        if self.monitor:
            self.monitor.stop()
        self.deployer.cleanup()
        log.info("[STOP] Framework shut down cleanly.")

    def restore(self):
        """
        Algorithm 6 — called after the user confirms the threat is gone.
        Restores ACLs and refreshes honeypots.
        """
        self.lockdown.restore_all()
        # Re-deploy fresh honeypots so the framework is reset
        self.honeypots = self.deployer.deploy(
            self.config["directories"],
            self.config.get("decoy_count", 3),
            self.config.get("file_types", FILE_TYPES),
        )
        if self.monitor:
            self.monitor.honeypots = self.honeypots
        self._triggered = False
        log.info("[RESTORE] Framework reset and honeypots redeployed.")

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------
    @staticmethod
    def _load_config(path: str) -> dict:
        """Load JSON config; fall back to sensible defaults."""
        try:
            with open(path, encoding="utf-8") as fh:
                cfg = json.load(fh)
            log.info(f"[CONFIG] Loaded: {path}")
            return cfg
        except FileNotFoundError:
            log.warning(f"[CONFIG] '{path}' not found — using built-in defaults.")
            home = Path.home()
            return {
                "directories": [
                    str(home / "Desktop"),
                    str(home / "Documents"),
                    str(home / "Downloads"),
                ],
                "decoy_count": 3,
                "file_types":  FILE_TYPES,
                "whitelist":   DEFAULT_WHITELIST,
            }

    @staticmethod
    def _setup_logging():
        ts  = datetime.now().strftime("%Y%m%d_%H%M%S")
        fmt = "%(asctime)s [%(levelname)8s] %(name)s: %(message)s"
        logging.basicConfig(
            level=logging.INFO,
            format=fmt,
            handlers=[
                logging.FileHandler(f"honeypot_{ts}.log", encoding="utf-8"),
                logging.StreamHandler(sys.stdout),
            ],
        )


def _banner():
    print("""
╔══════════════════════════════════════════════════════════════╗
║   HONEYPOT-DRIVEN RANSOMWARE DEFENCE FRAMEWORK               ║
║   OS Course Project  |  March 2025                          ║
║   Diamond Porwal  |  Bhupesh Bansal  |  Raghavendra Sani   ║
╚══════════════════════════════════════════════════════════════╝
""")
