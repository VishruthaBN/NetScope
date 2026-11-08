# NetScope

NetScope is a beginner-friendly Python TCP port checker for **authorized lab use**. It checks a single explicitly supplied host and a limited list of TCP ports, then reports whether each connection succeeded.

## Features

- Checks one hostname or IP address at a time
- Accepts comma-separated ports and ranges
- Sequential TCP connection checks (no stealth or evasion)
- Common service labels
- Human-readable or JSON output
- Input validation and a 256-port scan limit
- Unit tests using mocked network connections

## Requirements

- Python 3.10+
- No third-party packages

## Usage

Check your own computer:

```bash
python netscope.py --target 127.0.0.1
```

Check selected ports on a lab machine you are authorized to test:

```bash
python netscope.py --target 192.168.1.10 --ports 22,80,443
```

Check a small range and save structured output:

```bash
python netscope.py --target 127.0.0.1 --ports 1-100 --json
```

## Run tests

```bash
python -m unittest discover -s tests -v
```

## How it works

1. Validates the port list and timeout.
2. Resolves the supplied hostname to an IPv4 address.
3. Attempts a normal TCP connection to each requested port.
4. Reports `open` when the connection succeeds. A failed connection is shown as `closed|filtered`; this tool cannot distinguish a closed port from filtering.

## Limitations

- TCP only; it does not scan UDP.
- Sequential checks; not designed for high-speed scanning.
- Service names are common-port hints, not verified service detection.
- A failed connection does not prove a port is closed.

## Responsible use

Only scan devices and networks that you own or have explicit permission to test. Do not use this tool against public targets without authorization. Keep scans small and within the scope of your lab or assessment.

## Learning goals

This project demonstrates Python sockets, input validation, command-line interfaces, JSON output, unit testing, and basic TCP networking.
