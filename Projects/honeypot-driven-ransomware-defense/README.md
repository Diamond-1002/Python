# Honeypot-Driven Ransomware Defence Framework

A Windows-based ransomware defense system that detects and stops
ransomware in real time by planting decoy files, watching for suspicious
activity, freezing the offending process, and locking down folders before
real damage occurs.

## How to Use

```bash
# 1. Install dependencies (requires Python 3.10+ on Windows)
pip install -r requirements.txt

# 2. Run as Administrator (needed for process suspension & permission changes)
python main.py

# 3. Simulate a ransomware event (for demo/testing)
python main.py --simulate

# 4. Restore locked folders after clearing the threat
python restore.py

# 5. Check platform compatibility & dependency status
python main.py --status
```

## What the project does

This project detects ransomware the moment it starts encrypting files —
not after the damage is done. It works by planting fake, attractive-looking
files (honeypots) in common folders, then watching those specific files
closely. The instant a honeypot is touched, it's treated as a strong signal
of ransomware activity, and the framework immediately freezes the
responsible process and locks down the folder to stop it from spreading.

- **Deploys honeypot files** — realistic decoy files (e.g.
  `Important_Document_1234.docx`) hidden inside common user directories
  like Desktop, Documents, and Downloads.
- **Monitors the filesystem in real time** for renames, edits, or size
  changes on those honeypot files.
- **Identifies and freezes the responsible process** the moment a honeypot
  is touched, before it can encrypt more files.
- **Locks down folders** by rewriting permissions to block further write
  access, containing the threat.
- **Restores normal access** afterward once the threat has been cleared.

## Tech Used

- **Python** — core language for the entire framework.
- **pywin32** — provides access to Windows APIs for filesystem monitoring
  (`ReadDirectoryChangesW`) and file permission control (`SetFileSecurity`).
- **psutil** — used to inspect running processes and identify which one is
  responsible for touching a honeypot file.
- **ctypes + ntdll** — used to call low-level Windows functions directly,
  including `NtSuspendProcess` to freeze a malicious process instantly.
- **Windows ACL/security model** — used to lock down and later restore
  folder permissions.

## Key Benefits

- **Proactive, not reactive** — stops ransomware while it's happening,
  instead of just cleaning up after files are already encrypted.
- **Extremely fast response** — detection and process freezing happen in
  milliseconds, minimizing the number of files that could be lost.
- **Low overhead** — lightweight monitoring that runs quietly in the
  background without noticeably affecting system performance.
- **No file loss in most cases** — since honeypots are hit before real
  user files, the malicious process is stopped before real damage occurs.
- **Reversible protection** — folder lockdowns can be safely undone with
  the restore script once a threat has been cleared.

## Files

| File               | Purpose                                                      |
|--------------------|----------------------------------------------------------------|
| `main.py`          | CLI entry point — starts the framework and handles all commands |
| `framework.py`     | Core logic — honeypot deployment, monitoring, process isolation, and lockdown |
| `restore.py`       | Standalone script to undo folder lockdowns and restore access |
| `config.json`      | Configuration — which directories to protect, decoy settings, and process whitelist |
| `requirements.txt` | Python dependencies needed to run the framework               |

## How It Works (Detailed Walkthrough)

### 1. Honeypot Deployer
- Creates a set number of decoy files per protected directory with
  attractive, realistic names.
- Fills each file with random data so it looks like a real document.
- Hides the files so the user never sees or accidentally opens them.
- Keeps track of every honeypot's location for instant lookup.

### 2. Filesystem Monitor
- Watches each protected directory continuously for file activity.
- Detects renames, content changes, and size changes — the exact signs of
  a file being encrypted.
- The moment an event happens on a honeypot file, it immediately
  triggers the response process.
- Falls back to periodic checking if real-time monitoring isn't
  available.

### 3. Process Isolation Engine
- Figures out which running process currently has the honeypot file open.
- Checks that process against a safe list of trusted applications first.
- If it's not trusted, it's instantly frozen using a low-level system call,
  stopping all of its activity at once.
- If freezing isn't possible, the process is terminated instead.
- Displays an on-screen alert about the detected threat.

### 4. Folder Lockdown Manager
- Saves the folder's original permission settings before changing anything.
- Applies new, restrictive permissions that block further writes or
  deletions system-wide, while still allowing the system and current user
  basic read access.
- Once the threat is cleared, `restore.py` reverses this and returns the
  folder to normal permissions.

## Requirements

- Windows 10/11
- Python 3.10+
- Administrator privileges (required for process suspension and
  permission changes)
- Dependencies listed in `requirements.txt` (`pywin32`, `psutil`)
