import argparse
import json
import logging
import os
import ipaddress
from dataclasses import dataclass, asdict
from typing import List, Optional

# Configure logging
LOG_FILE = os.path.join(os.path.dirname(__file__), "firewall.log")
logging.basicConfig(filename=LOG_FILE, level=logging.INFO,
                    format='%(asctime)s - %(message)s')

@dataclass
class Rule:
    action: str  # "allow" or "block"
    ip: Optional[str] = None  # single IP or CIDR, e.g., "192.168.1.0/24"
    port: Optional[str] = None  # single port or range "80" or "8000-9000"
    protocol: Optional[str] = None  # "tcp", "udp", "icmp"

    def matches(self, ip: str, port: int, protocol: str) -> bool:
        """Return True if this rule matches the given packet attributes."""
        # IP match
        if self.ip:
            try:
                net = ipaddress.ip_network(self.ip, strict=False)
                if ipaddress.ip_address(ip) not in net:
                    return False
            except ValueError:
                # malformed rule – treat as non‑match
                return False
        # Port match
        if self.port:
            if '-' in self.port:
                start, end = map(int, self.port.split('-'))
                if not (start <= port <= end):
                    return False
            else:
                if port != int(self.port):
                    return False
        # Protocol match
        if self.protocol and self.protocol.lower() != protocol.lower():
            return False
        return True

class Firewall:
    def __init__(self, rule_file: str):
        self.rule_file = rule_file
        self.rules: List[Rule] = []
        self._load_rules()

    def _load_rules(self):
        if os.path.exists(self.rule_file):
            with open(self.rule_file, 'r') as f:
                data = json.load(f)
                self.rules = [Rule(**r) for r in data]
        else:
            self.rules = []

    def _save_rules(self):
        with open(self.rule_file, 'w') as f:
            json.dump([asdict(r) for r in self.rules], f, indent=2)

    def add_rule(self, rule: Rule):
        self.rules.append(rule)
        self._save_rules()
        logging.info(f"Added rule: {rule}")

    def remove_rule(self, index: int):
        if 0 <= index < len(self.rules):
            removed = self.rules.pop(index)
            self._save_rules()
            logging.info(f"Removed rule [{index}]: {removed}")
        else:
            raise IndexError("Rule index out of range")

    def list_rules(self):
        for i, rule in enumerate(self.rules):
            print(f"[{i}] {rule.action.upper():5} ip={rule.ip or '*'} port={rule.port or '*'} proto={rule.protocol or '*'}")

    def evaluate(self, ip: str, port: int, protocol: str) -> str:
        """Return "allow" or "block" for the given packet."""
        # Evaluate rules in order – first match wins
        for rule in self.rules:
            if rule.matches(ip, port, protocol):
                decision = rule.action
                logging.info(f"{decision.upper()} packet ip={ip} port={port} proto={protocol} matched rule {rule}")
                return decision
        # Default policy: block
        logging.info(f"BLOCK packet ip={ip} port={port} proto={protocol} – no matching rule")
        return "block"

def parse_rule_args(args) -> Rule:
    return Rule(
        action=args.action,
        ip=args.ip,
        port=args.port,
        protocol=args.protocol,
    )

def build_parser():
    parser = argparse.ArgumentParser(description="Simple firewall simulator")
    parser.add_argument('--rules', default='rules.json', help='Path to JSON rule file')
    sub = parser.add_subparsers(dest='command', required=True)

    # add-rule
    add = sub.add_parser('add-rule', help='Add a firewall rule')
    add.add_argument('action', choices=['allow', 'block'], help='Action for the rule')
    add.add_argument('--ip', help='IP address or CIDR (e.g., 192.168.1.0/24)')
    add.add_argument('--port', help='Port number or range (e.g., 80 or 8000-9000)')
    add.add_argument('--protocol', choices=['tcp', 'udp', 'icmp'], help='Protocol')

    # remove-rule
    rm = sub.add_parser('remove-rule', help='Remove a rule by its index')
    rm.add_argument('index', type=int, help='Index shown by list-rules')

    # list-rules
    sub.add_parser('list-rules', help='Show all configured rules')

    # test-packet
    test = sub.add_parser('test-packet', help='Test a packet against the rule set')
    test.add_argument('ip', help='Source IP address')
    test.add_argument('port', type=int, help='Destination port')
    test.add_argument('protocol', choices=['tcp', 'udp', 'icmp'], help='Protocol')

    return parser

def main():
    parser = build_parser()
    args = parser.parse_args()
    fw = Firewall(args.rules)

    if args.command == 'add-rule':
        rule = parse_rule_args(args)
        fw.add_rule(rule)
        print('Rule added.')
    elif args.command == 'remove-rule':
        try:
            fw.remove_rule(args.index)
            print('Rule removed.')
        except IndexError as e:
            print(e)
    elif args.command == 'list-rules':
        fw.list_rules()
    elif args.command == 'test-packet':
        decision = fw.evaluate(args.ip, args.port, args.protocol)
        print(f'Packet {decision.upper()}ed')

if __name__ == '__main__':
    main()
