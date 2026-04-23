#!/usr/bin/env python3
"""
SysmonForLinux Integration Test Runner

Main entry point for running all Linux Sysmon integration tests.
Must be run as root (sudo).

Usage:
    sudo python3 run_integration_tests.py [options]

Options:
    --verbose           Show detailed test output
    --tests TEST [...]  Run only specific test(s) by class name
    --list              List all available tests
    --sysmon-path PATH  Path to sysmon binary (default: /opt/sysmon/sysmon)
    --no-restore        Don't restore original config after tests
    --stop-on-failure   Stop at first test failure
"""

import argparse
import os
import sys
import time
from datetime import datetime, timezone

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from sysmon_test_framework import SysmonManager, SYSMON_BINARY, SYSMON_CONFIG
from test_events import ALL_TESTS


# ============================================================================
# Color Output
# ============================================================================

class Colors:
    RESET = "\033[0m"
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    BOLD = "\033[1m"

    @staticmethod
    def enabled():
        return hasattr(sys.stdout, "isatty") and sys.stdout.isatty()

    @classmethod
    def red(cls, s):
        return f"{cls.RED}{s}{cls.RESET}" if cls.enabled() else s

    @classmethod
    def green(cls, s):
        return f"{cls.GREEN}{s}{cls.RESET}" if cls.enabled() else s

    @classmethod
    def yellow(cls, s):
        return f"{cls.YELLOW}{s}{cls.RESET}" if cls.enabled() else s

    @classmethod
    def blue(cls, s):
        return f"{cls.BLUE}{s}{cls.RESET}" if cls.enabled() else s

    @classmethod
    def bold(cls, s):
        return f"{cls.BOLD}{s}{cls.RESET}" if cls.enabled() else s


# ============================================================================
# Test Runner
# ============================================================================

def save_current_config() -> str:
    """Save the current sysmon config so we can restore it later."""
    if os.path.exists(SYSMON_CONFIG):
        with open(SYSMON_CONFIG, "r") as f:
            return f.read()
    return ""


def restore_config(sysmon: SysmonManager, config_content: str):
    """Restore the original sysmon config."""
    if config_content:
        sysmon.apply_config(config_content)


def check_prerequisites(sysmon: SysmonManager) -> bool:
    """Check that all prerequisites are met."""
    errors = []

    # Must be root
    if os.geteuid() != 0:
        errors.append("Must be run as root (use sudo)")

    # Sysmon binary must exist
    if not os.path.isfile(sysmon.sysmon_path):
        errors.append(f"Sysmon binary not found at {sysmon.sysmon_path}")

    # Sysmon should be running
    if not sysmon.is_running():
        errors.append("Sysmon service is not running (install with: sudo sysmon -i config.xml)")

    # Python 3.6+
    if sys.version_info < (3, 6):
        errors.append(f"Python 3.6+ required (found {sys.version})")

    if errors:
        print(Colors.red("Prerequisites check FAILED:"))
        for err in errors:
            print(f"  - {err}")
        return False

    print(Colors.green("Prerequisites check passed"))
    return True


def run_tests(args):
    """Run the integration test suite."""
    sysmon = SysmonManager(sysmon_path=args.sysmon_path, verbose=args.verbose)

    print(Colors.bold("=" * 70))
    print(Colors.bold("SysmonForLinux Integration Tests"))
    print(Colors.bold("=" * 70))
    print(f"  Sysmon Path:  {args.sysmon_path}")
    print(f"  Time:         {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"  Verbose:      {args.verbose}")
    print()

    # Check prerequisites
    if not check_prerequisites(sysmon):
        return 1

    # Save original config
    original_config = ""
    if not args.no_restore:
        original_config = save_current_config()
        if original_config:
            print(f"  Saved original config from {SYSMON_CONFIG}")

    # Get list of tests to run
    if args.tests:
        test_map = {t.__name__: t for t in ALL_TESTS}
        tests_to_run = []
        for name in args.tests:
            if name in test_map:
                tests_to_run.append(test_map[name])
            else:
                print(Colors.red(f"Unknown test: {name}"))
                print(f"Available tests: {', '.join(test_map.keys())}")
                return 1
    else:
        tests_to_run = ALL_TESTS

    print(f"\n  Running {len(tests_to_run)} test(s)...\n")
    print("-" * 70)

    # Run tests
    results = []
    passed = 0
    failed = 0
    skipped = 0
    start_time = time.time()

    for test_class in tests_to_run:
        test = test_class(sysmon, verbose=args.verbose)
        result = test.run()
        results.append(result)

        # Print result line
        name = result.test_name
        duration = f"({result.duration:.1f}s)"

        if result.skipped:
            status = Colors.yellow(f"SKIP    {name} {duration}")
            reason = f" - {result.skip_reason}" if result.skip_reason else ""
            print(f"  {status}{reason}")
            skipped += 1
        elif result.passed:
            status = Colors.green(f"PASS    {name} {duration}")
            print(f"  {status}")
            passed += 1
        else:
            status = Colors.red(f"FAIL    {name} {duration}")
            print(f"  {status}")
            for err in result.errors:
                print(Colors.red(f"          -> {err}"))
            failed += 1

            if args.stop_on_failure:
                print(Colors.red("\n  Stopping on first failure."))
                break

    total_duration = time.time() - start_time

    # Restore config
    if not args.no_restore and original_config:
        print(f"\n  Restoring original configuration...")
        restore_config(sysmon, original_config)

    # Print summary
    print("\n" + "=" * 70)
    print(Colors.bold("TEST SUMMARY"))
    print("=" * 70)
    print(f"  Total:    {len(results)}")
    print(f"  Passed:   {Colors.green(str(passed))}")
    print(f"  Failed:   {Colors.red(str(failed))}")
    print(f"  Skipped:  {Colors.yellow(str(skipped))}")
    print(f"  Duration: {total_duration:.1f}s")
    print("=" * 70)

    if failed > 0:
        print(Colors.red("\nFailed tests:"))
        for r in results:
            if not r.passed and not r.skipped:
                print(Colors.red(f"  - {r.test_name}"))
                for err in r.errors:
                    print(Colors.red(f"      {err}"))

    print()
    return 0 if failed == 0 else 1


def list_tests():
    """List all available tests."""
    print("Available integration tests:\n")
    for test_class in ALL_TESTS:
        # Create a temporary instance to get the description
        name = test_class.__name__
        # Get description from docstring
        doc = test_class.__doc__ or ""
        first_line = doc.strip().split("\n")[0] if doc.strip() else ""
        print(f"  {name:40s} {first_line}")
    print(f"\nTotal: {len(ALL_TESTS)} tests")


# ============================================================================
# Main
# ============================================================================

def main():
    parser = argparse.ArgumentParser(
        description="SysmonForLinux Integration Test Runner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  sudo python3 run_integration_tests.py                    # Run all tests
  sudo python3 run_integration_tests.py --verbose          # Verbose output
  sudo python3 run_integration_tests.py --tests TestProcessCreate TestFileCreate
  sudo python3 run_integration_tests.py --list             # List all tests
"""
    )
    parser.add_argument("--verbose", "-v", action="store_true",
                        help="Show detailed test output")
    parser.add_argument("--tests", nargs="+", metavar="TEST",
                        help="Run only specific test(s) by class name")
    parser.add_argument("--list", "-l", action="store_true",
                        help="List all available tests")
    parser.add_argument("--sysmon-path", default=SYSMON_BINARY,
                        help=f"Path to sysmon binary (default: {SYSMON_BINARY})")
    parser.add_argument("--no-restore", action="store_true",
                        help="Don't restore original config after tests")
    parser.add_argument("--stop-on-failure", action="store_true",
                        help="Stop at first test failure")

    args = parser.parse_args()

    if args.list:
        list_tests()
        return 0

    return run_tests(args)


if __name__ == "__main__":
    sys.exit(main())
