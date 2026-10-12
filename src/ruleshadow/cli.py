import argparse
import json
import sys
from pathlib import Path
from .analysis import analyze
from .parsers import aws, azure, iptables


def main(argv=None):
    parser = argparse.ArgumentParser(description="Analyze local firewall rules for containment and sensitive exposure.")
    parser.add_argument("file", type=Path)
    parser.add_argument("--format", choices=("aws", "iptables", "azure"), required=True)
    parser.add_argument("--json", action="store_true", dest="as_json")
    args = parser.parse_args(argv)
    try:
        rules = {"aws": aws, "azure": azure, "iptables": iptables}[args.format].parse(args.file.read_text(encoding="utf-8-sig"))
        findings = analyze(rules, ordered=args.format != "aws")
    except (OSError, ValueError, KeyError, TypeError, AttributeError) as exc:
        print(f"ruleshadow: invalid input: {exc}", file=sys.stderr)
        return 2
    if args.as_json:
        print(json.dumps({"format": args.format, "rule_count": len(rules), "findings": [f.to_dict() for f in findings]}, indent=2))
    else:
        print(f"RuleShadow: {len(rules)} rules, {len(findings)} findings")
        for finding in findings:
            print(f"{finding.severity} {finding.kind} [{finding.rule_id}]: {finding.explanation}")
    return 0
