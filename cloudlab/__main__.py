import argparse
import json
from dataclasses import asdict
from pathlib import Path

from .scanner import SnapshotError, compare, scan


def assess_file(path):
    try:
        return scan(json.loads(path.read_text(encoding="utf-8")))
    except (OSError, ValueError) as exc:
        raise SnapshotError(f"{path}: {exc}") from exc


def main():
    parser = argparse.ArgumentParser(description="Assess local AWS lab snapshots.")
    commands = parser.add_subparsers(dest="command", required=True)
    scan_parser = commands.add_parser("scan", help="Report findings for one snapshot.")
    scan_parser.add_argument("snapshot", type=Path)
    compare_parser = commands.add_parser("compare", help="Verify the retest against a baseline.")
    compare_parser.add_argument("baseline", type=Path)
    compare_parser.add_argument("retest", type=Path)
    args = parser.parse_args()
    try:
        if args.command == "scan":
            result = assess_file(args.snapshot)
            payload = {
                "resources_assessed": len(result.inventory),
                "findings": [asdict(item) for item in result.findings],
            }
            print(json.dumps(payload, indent=2))
            return 0

        result = compare(assess_file(args.baseline), assess_file(args.retest))
        print("TradeLink remediation retest")
        for label, items in result.items():
            print(f"{label.replace('_', ' ').title()}: {len(items)}")
            for item in items:
                print(f"  {item.rule} [{item.severity}] {item.resource}")
        return int(bool(result["still_open"] or result["new"]))
    except SnapshotError as exc:
        parser.exit(2, f"error: {exc}\n")


if __name__ == "__main__":
    raise SystemExit(main())
