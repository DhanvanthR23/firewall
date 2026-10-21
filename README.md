# Simple Firewall Simulator

## Overview
The **firewall simulator** is a lightweight Python script that lets you manage firewall rules and evaluate traffic against those rules. It supports:

1. **IP‑based blocking/allowing** – individual IPs or CIDR blocks.
2. **Port filtering** – single ports or ranges (e.g., `80` or `8000‑9000`).
3. **Protocol filtering** – `tcp`, `udp`, or `icmp`.
4. **Rule ordering** – first matching rule wins, giving you fine‑grained control.
5. **Logging** – every decision (allow or block) is written to `firewall.log` with a timestamp.
6. **CLI** – add/remove/list rules and test packets via sub‑commands.

The script stores rules in a JSON file (`rules.json` by default) so that they persist between runs.

## How It Works
- **Rule definition** – Each rule is a `Rule` dataclass with fields `action`, `ip`, `port`, and `protocol`. Missing fields act as wildcards (match any).
- **Matching** – When a packet (IP, port, protocol) is evaluated, the firewall iterates over the rule list in order. The first rule whose criteria match the packet determines the decision (`allow` or `block`).
- **Default policy** – If no rule matches, the packet is blocked.
- **Logging** – Decisions are logged via Python’s `logging` module to `firewall.log` with the exact packet attributes and the rule that caused the decision.

## Example Usage
```bash
# Add a rule to block traffic from 10.0.0.0/8 on any port/protocol
python firewall.py add-rule block --ip 10.0.0.0/8

# Add a rule to allow TCP traffic to port 22 (SSH) from anywhere
python firewall.py add-rule allow --port 22 --protocol tcp

# List current rules
python firewall.py list-rules

# Test a packet – should be BLOCKed by the first rule
python firewall.py test-packet 10.1.2.3 443 tcp
# Output: Packet BLOCKED

# Test a packet – should be ALLOWed by the second rule
python firewall.py test-packet 203.0.113.5 22 tcp
# Output: Packet ALLOWED
```

## Test Cases (automated example)
You can verify the behaviour with a small shell script:
```bash
#!/usr/bin/env bash
set -e

# Reset rule set
rm -f rules.json firewall.log

# Add rules
python firewall.py add-rule block --ip 10.0.0.0/8
python firewall.py add-rule allow --port 22 --protocol tcp

# Expected outcomes
declare -A tests=(
  "10.1.2.3 443 tcp block"
  "203.0.113.5 22 tcp allow"
  "192.168.1.5 80 udp block"
)

for entry in "${tests[@]}"; do
  IFS=' ' read -r ip port proto expected <<< "$entry"
  result=$(python firewall.py test-packet $ip $port $proto | awk '{print $2}' | tr '[:upper:]' '[:lower:]')
  if [[ "$result" != "$expected" ]]; then
    echo "FAIL: $ip $port $proto – expected $expected, got $result"
    exit 1
  else
    echo "PASS: $ip $port $proto → $result"
  fi
done

echo "All tests passed"
``` 

Running this script should output `PASS` for each case and finish with `All tests passed`.

---
**Files created**
- `firewall.py` – the simulator implementation.
- `firewall_overview.md` – this explanation and test script.

Feel free to edit the rule file location with `--rules <path>` if you prefer a different name or location.
