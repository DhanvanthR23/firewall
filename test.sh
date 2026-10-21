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
  IFS=' ' read -r ip port proto expected <<<"$entry"
  result=$(
    python firewall.py test-packet $ip $port $proto | awk '{print $2}' | tr '[:upper:]'
    '[:lower:]'
  )
  if [[ "$result" != "$expected" ]]; then
    echo "FAIL: $ip $port $proto – expected $expected, got $result"
    exit 1
  else
    echo "PASS: $ip $port $proto → $result"
  fi
done

echo "All tests passed"
