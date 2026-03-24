#!/usr/bin/env python3
"""Filter TMAS scan results using exclusion rules.

Removes irrelevant detections (kernel vulns in containers, negligible severity,
disputed CVEs) and produces a filtered report with only actionable findings.

Usage:
    python filter-results.py tmas-results/vuln-scan.json tmas-exclusions.yaml
    python filter-results.py tmas-results/vuln-scan.json tmas-exclusions.yaml --output filtered.json
    python filter-results.py tmas-results/vuln-scan.json tmas-exclusions.yaml --summary
"""

import argparse
import json
import re
import sys
from pathlib import Path

import yaml


def load_exclusions(path: str) -> dict:
    with open(path) as f:
        return yaml.safe_load(f)


def matches_any(value: str, patterns: list[str]) -> bool:
    return any(re.search(p, value, re.IGNORECASE) for p in patterns)


SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "negligible": 0, "unimportant": 0}


def filter_vulnerabilities(vulns: list, exclusions: dict) -> tuple[list, list]:
    """Returns (kept, excluded) vulnerability lists."""
    kept = []
    excluded = []

    pkg_patterns = exclusions.get("exclude_packages", [])
    sev_exclude = [s.lower() for s in exclusions.get("exclude_severities", [])]
    cve_exclude = {c["cve"] for c in exclusions.get("exclude_cves", [])}
    downgrades = exclusions.get("downgrade_packages", [])
    cat_exclude = [c.lower() for c in exclusions.get("exclude_categories", [])]

    for v in vulns:
        pkg = v.get("package", v.get("packageName", ""))
        sev = v.get("severity", "").lower()
        cve = v.get("id", v.get("cve", ""))
        reason = None

        # Check severity exclusion
        if sev in sev_exclude:
            reason = f"excluded severity: {sev}"

        # Check package pattern exclusion
        elif matches_any(pkg, pkg_patterns):
            reason = f"excluded package pattern: {pkg}"

        # Check specific CVE exclusion
        elif cve in cve_exclude:
            reason = f"excluded CVE: {cve}"

        # Check category exclusion (kernel-related packages)
        elif "kernel" in cat_exclude and matches_any(pkg, [r"^linux-", r"^kernel-"]):
            reason = f"excluded category: kernel package {pkg}"

        # Check severity downgrade rules
        elif downgrades:
            for rule in downgrades:
                if matches_any(pkg, [rule["package"]]):
                    max_sev = rule["max_severity"].lower()
                    if SEVERITY_ORDER.get(sev, 0) < SEVERITY_ORDER.get(max_sev, 0):
                        reason = f"below threshold for {pkg}: {sev} < {max_sev}"
                        break

        if reason:
            v["_excluded"] = True
            v["_exclusion_reason"] = reason
            excluded.append(v)
        else:
            kept.append(v)

    return kept, excluded


def main():
    parser = argparse.ArgumentParser(description="Filter TMAS scan results")
    parser.add_argument("scan_results", help="Path to TMAS JSON scan results")
    parser.add_argument("exclusions", help="Path to exclusions YAML")
    parser.add_argument("--output", "-o", help="Output path (default: stdout)")
    parser.add_argument("--summary", "-s", action="store_true", help="Print summary only")
    args = parser.parse_args()

    with open(args.scan_results) as f:
        scan = json.load(f)

    exclusions = load_exclusions(args.exclusions)

    # Find vulnerability list in scan results (TMAS schema varies)
    vulns = (
        scan.get("vulnerabilities")
        or scan.get("vulnerability", {}).get("vulnerabilities")
        or []
    )

    kept, excluded = filter_vulnerabilities(vulns, exclusions)

    # Count by severity
    def count_by_sev(items):
        counts = {}
        for v in items:
            s = v.get("severity", "unknown").lower()
            counts[s] = counts.get(s, 0) + 1
        return counts

    result = {
        "filtered_vulnerabilities": kept,
        "excluded_vulnerabilities": excluded,
        "summary": {
            "total_before": len(vulns),
            "total_after": len(kept),
            "excluded_count": len(excluded),
            "reduction_pct": round(len(excluded) / max(len(vulns), 1) * 100, 1),
            "kept_by_severity": count_by_sev(kept),
            "excluded_by_severity": count_by_sev(excluded),
            "exclusion_reasons": {}
        }
    }

    # Group exclusion reasons
    for v in excluded:
        reason = v.get("_exclusion_reason", "unknown")
        result["summary"]["exclusion_reasons"][reason] = result["summary"]["exclusion_reasons"].get(reason, 0) + 1

    if args.summary:
        s = result["summary"]
        print(f"Before filter: {s['total_before']} vulnerabilities")
        print(f"After filter:  {s['total_after']} vulnerabilities")
        print(f"Excluded:      {s['excluded_count']} ({s['reduction_pct']}%)")
        print(f"\nKept by severity:    {json.dumps(s['kept_by_severity'])}")
        print(f"Excluded by severity: {json.dumps(s['excluded_by_severity'])}")
        print(f"\nExclusion reasons:")
        for reason, count in sorted(s["exclusion_reasons"].items(), key=lambda x: -x[1]):
            print(f"  {count:4d}  {reason}")
        return

    output = json.dumps(result, indent=2)
    if args.output:
        Path(args.output).write_text(output)
        print(f"Filtered results written to {args.output}", file=sys.stderr)
        s = result["summary"]
        print(f"{s['total_before']} → {s['total_after']} vulns ({s['excluded_count']} excluded, {s['reduction_pct']}% reduction)", file=sys.stderr)
    else:
        print(output)


if __name__ == "__main__":
    main()
