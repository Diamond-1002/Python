# Port Scanner

A simple Python-based TCP port scanner that checks a target host for open
ports by attempting a connection to each one, reporting back exactly
which ports are accepting connections.

## How to Use

```bash
# Run the scanner against a target IP address or hostname
python Port_scanner.py <target>

# Examples
python Port_scanner.py 192.168.1.1
python Port_scanner.py example.com
```

## What the project does

This script performs a full **TCP connect scan** against a given target,
checking every port from 1 to 65534 to see if it's open. For each open
port found, it prints it to the terminal in real time, giving a quick
overview of which services might be running and reachable on that host.

- Takes a **target IP or hostname** as a command-line argument and
  resolves it to an IP address.
- Prints a scan banner showing the target and the exact time the scan
  started.
- Iterates through **all 65,535 TCP ports**, attempting a connection to
  each one.
- Reports every port that responds successfully as `OPEN`.
- Handles common errors gracefully — invalid hostnames, connection
  issues, and manual interruption (`Ctrl+C`) all exit cleanly instead of
  crashing.

## Tech Used

- **Python** — the entire scanner is a single self-contained script.
- **`socket`** — Python's built-in networking module, used to open raw
  TCP connections to each port and check whether they succeed.
- **`datetime`** — used to timestamp when the scan begins.
- **`sys`** — used to read command-line arguments and exit cleanly on
  errors or interruption.

## Key Benefits

- **No external dependencies** — built entirely from Python's standard
  library, so it runs anywhere Python is installed with zero setup.
- **Simple and readable** — a great example of how port scanning works
  at its core, without the complexity of a full scanning framework.
- **Immediate feedback** — open ports are printed as soon as they're
  found, rather than waiting for the entire scan to finish.
- **Graceful error handling** — invalid hosts, network errors, and
  manual cancellation are all handled without ugly crash output.
- **Great learning tool** — demonstrates core networking concepts like
  sockets, connection attempts, and timeouts in a short, easy-to-follow
  script.

## Files

| File                | Purpose                                   |
|---------------------|---------------------------------------------|
| `Port_scanner.py`   | The port scanning script                   |

## How It Works (Detailed Walkthrough)

1. **Reads the target** from the command line (`sys.argv`). If no target
   is provided, it prints a usage error and exits.
2. **Resolves the hostname** to an IP address using
   `socket.gethostbyname()`, so it works whether you pass a domain name
   or a raw IP.
3. **Prints a scan banner** showing the resolved target and the exact
   time the scan started, using `datetime.now()`.
4. **Sets a connection timeout** of 1 second per port
   (`socket.setdefaulttimeout(1)`), so the scan doesn't hang indefinitely
   on unresponsive ports.
5. **Loops through every port from 1 to 65534**, creating a new TCP
   socket each time and attempting to connect to it with
   `s.connect_ex()`.
   - A return value of `0` means the connection succeeded — the port is
     open — and it's printed immediately.
   - Any other return value means the port is closed or filtered, and
     the scanner moves on.
6. **Closes each socket** after checking it, to avoid leaking open file
   descriptors during the scan.
7. **Handles exceptions** cleanly:
   - `KeyboardInterrupt` — lets you stop the scan early with `Ctrl+C`.
   - `socket.gaierror` — triggered if the hostname can't be resolved.
   - `socket.error` — triggered on general connection failures.

## Requirements

- Python 3.x (uses only standard library modules — no installation
  needed)
