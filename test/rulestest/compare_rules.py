#!/usr/bin/env python3
"""
SysmonForLinux Rules Blob Comparison Test

Compares the rules blob (compiled config output) between two sysmon binaries
to verify that the pugixml-based parser produces identical rules to libxml2.

Usage: sudo python3 compare_rules.py [--verbose]
"""

import os
import sys
import subprocess
import tempfile
import difflib
import glob
import argparse
from pathlib import Path


SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIGS_DIR = os.path.join(SCRIPT_DIR, "configs")
BASELINE_DIR = os.path.join(SCRIPT_DIR, "baseline")
OLD_SYSMON = "/home/chakra/repos/SysmonForLinuxOld/build/sysmon"
NEW_SYSMON = "/home/chakra/repos/SysmonForLinux/build/sysmon"


def get_rules_dump(sysmon_binary, config_file, verbose=False):
    """
    Apply a config file to sysmon and get the compiled rules dump.

    Instead of installing sysmon (which requires eBPF), we use the -c flag
    on a running instance OR parse the config and dump. Since we need to
    compare two different binaries, we:
    1. Install with the config using the target binary
    2. Dump the config using the same binary
    3. Uninstall

    Alternative approach: use the binary to just validate and dump the config.
    The -c flag on a running sysmon changes the config and dumps it.
    For non-running sysmon, we check if -c can still dump.
    """
    # First, try using the sysmon binary to just parse and validate the config
    # The key output we want is the "Rule configuration" dump
    result = subprocess.run(
        ["sudo", sysmon_binary, "-i", config_file],
        capture_output=True, text=True, timeout=30
    )

    install_output = result.stdout + result.stderr
    install_rc = result.returncode

    if verbose:
        print(f"    Install exit={install_rc}")

    # Now dump the compiled rules
    result = subprocess.run(
        ["sudo", sysmon_binary, "-c"],
        capture_output=True, text=True, timeout=30
    )

    dump_output = result.stdout + result.stderr
    dump_rc = result.returncode

    # Uninstall
    subprocess.run(
        ["sudo", sysmon_binary, "-u", "force"],
        capture_output=True, text=True, timeout=30
    )
    import time
    time.sleep(2)

    # Extract just the rules portion from the dump
    rules_lines = extract_rules(dump_output)

    return {
        "install_rc": install_rc,
        "install_output": install_output,
        "dump_rc": dump_rc,
        "dump_output": dump_output,
        "rules": rules_lines,
    }


def extract_rules(dump_output):
    """Extract the rule configuration lines from sysmon -c output."""
    lines = dump_output.split("\n")
    rules_lines = []
    in_rules = False

    for line in lines:
        # Skip banner lines
        if "Sysmon v" in line or "Sysinternals" in line or "Mark Russinovich" in line:
            continue
        if "Copyright" in line or "Licensed under" in line or "Using " in line:
            continue
        if line.strip() == "":
            if in_rules:
                rules_lines.append("")
            continue

        if "Rule configuration" in line or "configuration (version" in line:
            in_rules = True
            rules_lines.append(line.strip())
            continue

        if in_rules:
            rules_lines.append(line.rstrip())

    # Remove trailing empty lines
    while rules_lines and rules_lines[-1].strip() == "":
        rules_lines.pop()

    return rules_lines


def normalize_rules(rules_lines):
    """Normalize rules for comparison (strip whitespace variations)."""
    normalized = []
    for line in rules_lines:
        # Normalize whitespace but preserve structure
        stripped = line.rstrip()
        normalized.append(stripped)
    return normalized


def compare_rules(old_rules, new_rules):
    """Compare two rules dumps and return diff."""
    old_norm = normalize_rules(old_rules)
    new_norm = normalize_rules(new_rules)

    if old_norm == new_norm:
        return True, []

    diff = list(difflib.unified_diff(
        old_norm, new_norm,
        fromfile="libxml2 (old)",
        tofile="pugixml (new)",
        lineterm=""
    ))

    return False, diff


def main():
    parser = argparse.ArgumentParser(description="Compare rules blobs between two sysmon builds")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")
    parser.add_argument("--baseline", "-b", action="store_true",
                        help="Compare new sysmon against saved baseline files (no old binary needed)")
    parser.add_argument("--baseline-dir", default=BASELINE_DIR,
                        help="Directory containing baseline .rules files (default: test/rulestest/baseline/)")
    parser.add_argument("--old-sysmon", default=OLD_SYSMON, help="Path to old (libxml2) sysmon binary")
    parser.add_argument("--new-sysmon", default=NEW_SYSMON, help="Path to new (pugixml) sysmon binary")
    parser.add_argument("--configs-dir", default=CONFIGS_DIR, help="Directory containing test configs")
    parser.add_argument("--output-dir", default=None, help="Directory to save rule dumps")
    args = parser.parse_args()

    if os.geteuid() != 0:
        print("ERROR: Must run as root (sudo)")
        sys.exit(1)

    # In baseline mode, only the new binary is needed
    if args.baseline:
        if not os.path.isdir(args.baseline_dir):
            print(f"ERROR: Baseline directory not found: {args.baseline_dir}")
            sys.exit(1)
        baseline_files = sorted(glob.glob(os.path.join(args.baseline_dir, "*.rules")))
        if not baseline_files:
            print(f"ERROR: No baseline .rules files found in {args.baseline_dir}")
            sys.exit(1)
        for label, path in [("New (pugixml)", args.new_sysmon)]:
            if not os.path.isfile(path):
                print(f"ERROR: {label} binary not found: {path}")
                sys.exit(1)
            if not os.access(path, os.X_OK):
                print(f"ERROR: {label} binary not executable: {path}")
                sys.exit(1)
    else:
        # Verify both binaries exist
        for label, path in [("Old (libxml2)", args.old_sysmon), ("New (pugixml)", args.new_sysmon)]:
            if not os.path.isfile(path):
                print(f"ERROR: {label} binary not found: {path}")
                sys.exit(1)
            if not os.access(path, os.X_OK):
                print(f"ERROR: {label} binary not executable: {path}")
                sys.exit(1)

    # Find all config files
    config_files = sorted(glob.glob(os.path.join(args.configs_dir, "*.xml")))
    if not config_files:
        print(f"ERROR: No config files found in {args.configs_dir}")
        sys.exit(1)

    # In baseline mode, only use configs that have a matching baseline file
    if args.baseline:
        baseline_names = {os.path.basename(f).replace(".rules", "")
                          for f in glob.glob(os.path.join(args.baseline_dir, "*.rules"))}
        config_files = [c for c in config_files
                        if os.path.basename(c).replace(".xml", "") in baseline_names]
        if not config_files:
            print(f"ERROR: No config files match baseline files")
            sys.exit(1)

    # Set up output directory
    output_dir = args.output_dir
    if output_dir is None:
        output_dir = tempfile.mkdtemp(prefix="sysmon_rules_compare_")
    os.makedirs(output_dir, exist_ok=True)
    new_dir = os.path.join(output_dir, "new_pugixml")
    os.makedirs(new_dir, exist_ok=True)
    if not args.baseline:
        old_dir = os.path.join(output_dir, "old_libxml2")
        os.makedirs(old_dir, exist_ok=True)

    print("=" * 70)
    print("SysmonForLinux Rules Blob Comparison Test")
    print("=" * 70)
    if args.baseline:
        print(f"  Mode:                 BASELINE (comparing against saved reference)")
        print(f"  Baseline directory:   {args.baseline_dir}")
        print(f"  New binary (pugixml): {args.new_sysmon}")
    else:
        print(f"  Mode:                 DUAL-BINARY (running both old and new)")
        print(f"  Old binary (libxml2): {args.old_sysmon}")
        print(f"  New binary (pugixml): {args.new_sysmon}")
    print(f"  Config files:         {len(config_files)}")
    print(f"  Output directory:     {output_dir}")
    print()

    # Make sure sysmon is not running
    if not args.baseline:
        subprocess.run(["sudo", args.old_sysmon, "-u", "force"],
                       capture_output=True, timeout=15)
    subprocess.run(["sudo", args.new_sysmon, "-u", "force"],
                   capture_output=True, timeout=15)
    import time
    time.sleep(2)

    total = 0
    passed = 0
    failed = 0
    errors = 0
    results = []

    for config_file in config_files:
        config_name = os.path.basename(config_file)
        total += 1

        print(f"  [{total:2d}/{len(config_files)}] {config_name}", end=" ... ", flush=True)

        try:
            if args.baseline:
                # BASELINE MODE: read old rules from saved file, generate new rules
                baseline_file = os.path.join(
                    args.baseline_dir,
                    config_name.replace(".xml", ".rules")
                )
                with open(baseline_file, "r") as f:
                    old_rules = f.read().split("\n")
                # Remove trailing empty lines to match extract_rules behavior
                while old_rules and old_rules[-1].strip() == "":
                    old_rules.pop()

                if args.verbose:
                    print()
                    print(f"    Loaded baseline: {baseline_file}")
                    print(f"    Running NEW (pugixml)...")
                new_result = get_rules_dump(args.new_sysmon, config_file, args.verbose)

                # Save new dump
                new_dump_file = os.path.join(new_dir, config_name.replace(".xml", ".rules"))
                with open(new_dump_file, "w") as f:
                    f.write("\n".join(new_result["rules"]))

                # Compare rules
                match, diff = compare_rules(old_rules, new_result["rules"])

                if match:
                    print("MATCH")
                    passed += 1
                    results.append({
                        "config": config_name,
                        "status": "MATCH",
                        "reason": "Rules match baseline",
                    })
                else:
                    print("DIFF")
                    failed += 1
                    diff_text = "\n".join(diff)
                    results.append({
                        "config": config_name,
                        "status": "DIFF",
                        "reason": "Rules differ from baseline",
                        "diff": diff_text,
                    })
                    if args.verbose:
                        print(f"    --- DIFF ---")
                        for d in diff[:30]:
                            print(f"    {d}")
                        if len(diff) > 30:
                            print(f"    ... ({len(diff) - 30} more lines)")

            else:
                # DUAL-BINARY MODE: run both old and new sysmon
                # Generate rules with OLD sysmon (libxml2)
                if args.verbose:
                    print()
                    print(f"    Running OLD (libxml2)...")
                old_result = get_rules_dump(args.old_sysmon, config_file, args.verbose)

                # Generate rules with NEW sysmon (pugixml)
                if args.verbose:
                    print(f"    Running NEW (pugixml)...")
                new_result = get_rules_dump(args.new_sysmon, config_file, args.verbose)

                # Save dumps
                old_dump_file = os.path.join(old_dir, config_name.replace(".xml", ".rules"))
                new_dump_file = os.path.join(new_dir, config_name.replace(".xml", ".rules"))
                with open(old_dump_file, "w") as f:
                    f.write("\n".join(old_result["rules"]))
                with open(new_dump_file, "w") as f:
                    f.write("\n".join(new_result["rules"]))

                # Check install return codes match
                if old_result["install_rc"] != new_result["install_rc"]:
                    print(f"DIFF (install exit: old={old_result['install_rc']}, new={new_result['install_rc']})")
                    failed += 1
                    results.append({
                        "config": config_name,
                        "status": "DIFF",
                        "reason": f"Install exit code differs: old={old_result['install_rc']}, new={new_result['install_rc']}",
                    })
                    continue

                # If both failed to install, that's a match (both reject the config)
                if old_result["install_rc"] != 0 and new_result["install_rc"] != 0:
                    print(f"MATCH (both rejected, exit={old_result['install_rc']})")
                    passed += 1
                    results.append({
                        "config": config_name,
                        "status": "MATCH",
                        "reason": f"Both rejected config with exit={old_result['install_rc']}",
                    })
                    continue

                # Compare rules dumps
                match, diff = compare_rules(old_result["rules"], new_result["rules"])

                if match:
                    print("MATCH")
                    passed += 1
                    results.append({
                        "config": config_name,
                        "status": "MATCH",
                        "reason": "Rules blobs identical",
                    })
                else:
                    print("DIFF")
                    failed += 1
                    diff_text = "\n".join(diff)
                    results.append({
                        "config": config_name,
                        "status": "DIFF",
                        "reason": "Rules blobs differ",
                        "diff": diff_text,
                    })
                    if args.verbose:
                        print(f"    --- DIFF ---")
                        for d in diff[:30]:
                            print(f"    {d}")
                        if len(diff) > 30:
                            print(f"    ... ({len(diff) - 30} more lines)")

        except Exception as e:
            print(f"ERROR: {e}")
            errors += 1
            results.append({
                "config": config_name,
                "status": "ERROR",
                "reason": str(e),
            })

    # Summary
    print()
    print("=" * 70)
    print("RESULTS SUMMARY")
    print("=" * 70)
    print(f"  Total configs:  {total}")
    print(f"  Matched:        {passed}")
    print(f"  Differed:       {failed}")
    print(f"  Errors:         {errors}")
    print(f"  Output saved:   {output_dir}")
    print()

    if failed > 0:
        print("DIFFERENCES FOUND:")
        for r in results:
            if r["status"] == "DIFF":
                print(f"  {r['config']}: {r['reason']}")
                if "diff" in r:
                    for line in r["diff"].split("\n")[:20]:
                        print(f"    {line}")
                    diff_lines = r["diff"].split("\n")
                    if len(diff_lines) > 20:
                        print(f"    ... ({len(diff_lines) - 20} more lines)")
        print()

    if errors > 0:
        print("ERRORS:")
        for r in results:
            if r["status"] == "ERROR":
                print(f"  {r['config']}: {r['reason']}")
        print()

    # Save full report
    report_file = os.path.join(output_dir, "comparison_report.txt")
    with open(report_file, "w") as f:
        f.write(f"SysmonForLinux Rules Blob Comparison\n")
        f.write(f"{'='*70}\n")
        if args.baseline:
            f.write(f"Mode: BASELINE\n")
            f.write(f"Baseline dir: {args.baseline_dir}\n")
        else:
            f.write(f"Mode: DUAL-BINARY\n")
            f.write(f"Old binary: {args.old_sysmon}\n")
        f.write(f"New binary: {args.new_sysmon}\n")
        f.write(f"Total: {total}, Matched: {passed}, Differed: {failed}, Errors: {errors}\n\n")
        for r in results:
            f.write(f"{r['config']}: {r['status']} - {r['reason']}\n")
            if "diff" in r:
                f.write(f"{r['diff']}\n\n")

    print(f"Full report: {report_file}")
    print("=" * 70)

    sys.exit(0 if failed == 0 and errors == 0 else 1)


if __name__ == "__main__":
    main()
