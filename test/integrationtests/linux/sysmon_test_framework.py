#!/usr/bin/env python3
"""
SysmonForLinux Integration Test Framework

Core framework for reading, filtering, and asserting on Sysmon events
from syslog. Adapted from the Windows C# integration test framework.
"""

import os
import re
import sys
import time
import subprocess
import tempfile
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Callable, Tuple

# ============================================================================
# Constants
# ============================================================================

SYSMON_BINARY = "/opt/sysmon/sysmon"
SYSMON_LOGVIEW = "/opt/sysmon/sysmonLogView"
SYSMON_CONFIG = "/opt/sysmon/config.xml"
SYSMON_INSTALL_DIR = "/opt/sysmon"
SCHEMA_VERSION = "4.90"

# Default timeouts - generous to handle sysmon event backlogs
DEFAULT_WAIT_SECONDS = 60
DEFAULT_POLL_INTERVAL = 2.0


# ============================================================================
# Event IDs (mirrors Windows Events.cs)
# ============================================================================

class EventIds:
    SYSMON_ERROR = 255
    SYSMON_CREATE_PROCESS = 1
    SYSMON_FILE_TIME = 2
    SYSMON_NETWORK_CONNECT = 3
    SYSMON_SERVICE_STATE_CHANGE = 4
    SYSMON_PROCESS_TERMINATE = 5
    SYSMON_DRIVER_LOAD = 6
    SYSMON_IMAGE_LOAD = 7
    SYSMON_CREATE_REMOTE_THREAD = 8
    SYSMON_RAWACCESS_READ = 9
    SYSMON_ACCESS_PROCESS = 10
    SYSMON_FILE_CREATE = 11
    SYSMON_REG_KEY = 12
    SYSMON_REG_SETVALUE = 13
    SYSMON_REG_NAME = 14
    SYSMON_FILE_CREATE_STREAM_HASH = 15
    SYSMON_SERVICE_CONFIGURATION_CHANGE = 16
    SYSMON_CREATE_NAMEDPIPE = 17
    SYSMON_CONNECT_NAMEDPIPE = 18
    SYSMON_DNS_QUERY = 22
    SYSMON_FILE_DELETE = 23
    SYSMON_CLIPBOARD = 24
    SYSMON_PROCESS_IMAGE_TAMPERING = 25
    SYSMON_FILE_DELETE_DETECTED = 26

    @staticmethod
    def name(event_id: int) -> str:
        names = {
            255: "Error",
            1: "ProcessCreate",
            2: "FileCreateTime",
            3: "NetworkConnect",
            4: "ServiceStateChange",
            5: "ProcessTerminate",
            6: "DriverLoad",
            7: "ImageLoad",
            8: "CreateRemoteThread",
            9: "RawAccessRead",
            10: "ProcessAccess",
            11: "FileCreate",
            12: "RegistryKeyCreated",
            13: "RegistryValueSet",
            14: "RegistryKeyRenamed",
            15: "FileCreateStreamHash",
            16: "ConfigChange",
            17: "PipeCreated",
            18: "PipeConnected",
            22: "DnsQuery",
            23: "FileDelete",
            24: "ClipboardChanged",
            25: "ProcessImageTampering",
            26: "FileDeleteDetected",
        }
        return names.get(event_id, f"Unknown({event_id})")


# ============================================================================
# Event Entry
# ============================================================================

@dataclass
class EventEntry:
    """Represents a single Sysmon event parsed from syslog."""
    event_id: int
    properties: Dict[str, str] = field(default_factory=dict)
    system_time: Optional[str] = None
    event_record_id: Optional[int] = None
    computer: Optional[str] = None
    raw_xml: Optional[str] = None

    def __str__(self):
        props = ", ".join(f"{k}={v}" for k, v in self.properties.items())
        return f"Event[{EventIds.name(self.event_id)}({self.event_id})] {props}"

    def get(self, key: str, default: str = "") -> str:
        return self.properties.get(key, default)


# ============================================================================
# Event Filter
# ============================================================================

@dataclass
class FilterDesc:
    """Describes filter criteria for matching events."""
    match_all: bool = False
    filters: List[Tuple[str, str]] = field(default_factory=list)

    def __init__(self, match_all: bool = False, **kwargs):
        self.match_all = match_all
        self.filters = [(k, v) for k, v in kwargs.items()]

    @classmethod
    def from_pairs(cls, match_all: bool, *pairs):
        """Create from alternating key, value pairs."""
        obj = cls(match_all=match_all)
        if len(pairs) % 2 != 0:
            raise ValueError("Pairs must have even length (key, value, key, value, ...)")
        obj.filters = [(pairs[i], pairs[i+1]) for i in range(0, len(pairs), 2)]
        return obj

    def match(self, entry: EventEntry) -> bool:
        if not self.filters:
            return True

        matched_count = 0
        for key, pattern in self.filters:
            value = entry.properties.get(key, "")
            if re.search(pattern, value, re.IGNORECASE):
                matched_count += 1
                if not self.match_all:
                    return True

        if self.match_all:
            return matched_count == len(self.filters)
        return False


@dataclass
class EventFilterResult:
    """Result of event filtering."""
    match: List[EventEntry] = field(default_factory=list)
    not_matched: List[EventEntry] = field(default_factory=list)


# ============================================================================
# Event Reader - Reads Sysmon events from syslog/journald
# ============================================================================

class EventReader:
    """Reads and parses Sysmon events from syslog or journald."""

    @staticmethod
    def parse_event_xml(xml_str: str) -> Optional[EventEntry]:
        """Parse a single Sysmon XML event string."""
        try:
            root = ET.fromstring(xml_str)
        except ET.ParseError:
            return None

        # Namespace handling
        ns = ""
        if root.tag.startswith("{"):
            ns = root.tag.split("}")[0] + "}"

        # Parse System
        system = root.find(f"{ns}System")
        if system is None:
            return None

        event_id_elem = system.find(f"{ns}EventID")
        if event_id_elem is None:
            return None

        try:
            event_id = int(event_id_elem.text)
        except (ValueError, TypeError):
            return None

        entry = EventEntry(event_id=event_id, raw_xml=xml_str)

        time_created = system.find(f"{ns}TimeCreated")
        if time_created is not None:
            entry.system_time = time_created.get("SystemTime", "")

        record_id = system.find(f"{ns}EventRecordID")
        if record_id is not None and record_id.text:
            try:
                entry.event_record_id = int(record_id.text)
            except ValueError:
                pass

        computer = system.find(f"{ns}Computer")
        if computer is not None and computer.text:
            entry.computer = computer.text

        # Parse EventData
        event_data = root.find(f"{ns}EventData")
        if event_data is not None:
            for data in event_data.findall(f"{ns}Data"):
                name = data.get("Name", "")
                value = data.text or ""
                if name:
                    entry.properties[name] = value

        return entry

    @staticmethod
    def read_from_syslog(since_time: Optional[datetime] = None,
                         max_events: int = 50000) -> List[EventEntry]:
        """Read Sysmon events from syslog via journalctl."""
        entries = []

        cmd = [
            "journalctl", "_COMM=sysmon",
            "--no-pager", "-o", "cat",
            f"-n{max_events}"
        ]

        if since_time:
            # journalctl --since expects local time or explicit UTC
            # Convert UTC datetime to local time string for journalctl
            if since_time.tzinfo is not None:
                local_time = since_time.astimezone()
                time_str = local_time.strftime("%Y-%m-%d %H:%M:%S")
            else:
                time_str = since_time.strftime("%Y-%m-%d %H:%M:%S")
            cmd.extend(["--since", time_str])

        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            lines = result.stdout.strip().split("\n")
        except (subprocess.TimeoutExpired, FileNotFoundError):
            # Fallback: grep syslog directly
            return EventReader._read_from_syslog_file(since_time, max_events)

        for line in lines:
            line = line.strip()
            if not line:
                continue

            # Extract XML from the syslog line
            xml_start = line.find("<Event>")
            if xml_start == -1:
                xml_start = line.find("<Event ")
            if xml_start == -1:
                continue

            xml_str = line[xml_start:]
            entry = EventReader.parse_event_xml(xml_str)
            if entry is not None:
                entries.append(entry)

        return entries

    @staticmethod
    def _read_from_syslog_file(since_time: Optional[datetime] = None,
                                max_events: int = 50000) -> List[EventEntry]:
        """Fallback: read from /var/log/syslog directly."""
        entries = []
        syslog_path = "/var/log/syslog"

        if not os.path.exists(syslog_path):
            return entries

        try:
            cmd = ["grep", "sysmon", syslog_path]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            lines = result.stdout.strip().split("\n")
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return entries

        for line in lines[-max_events:]:
            xml_start = line.find("<Event>")
            if xml_start == -1:
                xml_start = line.find("<Event ")
            if xml_start == -1:
                continue

            xml_str = line[xml_start:]
            entry = EventReader.parse_event_xml(xml_str)
            if entry is not None:
                entries.append(entry)

        return entries


# ============================================================================
# Event Filter Operations
# ============================================================================

class EventFilter:
    """Provides event searching and filtering similar to the C# EventFilter class."""

    @staticmethod
    def find_events(event_id: int,
                    filter_desc: FilterDesc,
                    since_time: Optional[datetime] = None,
                    wait_seconds: int = 0,
                    expected_matches: int = 1) -> EventFilterResult:
        """
        Find Sysmon events matching criteria, optionally waiting for them.

        Uses unique filter criteria (markers) for reliable matching rather
        than time-based filtering, since sysmon may have event backlogs.

        Args:
            event_id: The Sysmon event ID to search for
            filter_desc: Filter criteria for matching
            since_time: Hint for journalctl (not used for strict filtering)
            wait_seconds: Maximum seconds to wait for expected matches
            expected_matches: Minimum matches to wait for (when wait_seconds > 0)
        """
        start = time.time()

        while True:
            # Read all recent events (don't rely on since_time for filtering)
            all_events = EventReader.read_from_syslog(since_time=None)

            # Filter by event ID
            id_matched = [e for e in all_events if e.event_id == event_id]

            # Apply filter (unique markers handle identification)
            matched = []
            not_matched = []
            for e in id_matched:
                if filter_desc.match(e):
                    matched.append(e)
                else:
                    not_matched.append(e)

            if not wait_seconds or len(matched) >= expected_matches:
                return EventFilterResult(match=matched, not_matched=not_matched)

            elapsed = time.time() - start
            if elapsed >= wait_seconds:
                return EventFilterResult(match=matched, not_matched=not_matched)

            time.sleep(DEFAULT_POLL_INTERVAL)

    @staticmethod
    def find_quick(event_id: int, filter_desc: FilterDesc,
                   since_time: Optional[datetime] = None) -> EventFilterResult:
        return EventFilter.find_events(event_id, filter_desc, since_time)

    @staticmethod
    def find_quick_wait(event_id: int, filter_desc: FilterDesc,
                        since_time: Optional[datetime] = None,
                        wait_seconds: int = DEFAULT_WAIT_SECONDS,
                        expected_matches: int = 1) -> EventFilterResult:
        return EventFilter.find_events(event_id, filter_desc, since_time,
                                       wait_seconds, expected_matches)


# ============================================================================
# Sysmon Manager
# ============================================================================

class SysmonManager:
    """Manages Sysmon installation, config, and service lifecycle."""

    def __init__(self, sysmon_path: str = SYSMON_BINARY, verbose: bool = False):
        self.sysmon_path = sysmon_path
        self.verbose = verbose

    def run_sysmon(self, args: str, check: bool = True) -> Tuple[int, str, str]:
        cmd = f"sudo {self.sysmon_path} {args}"
        if self.verbose:
            print(f"  [CMD] {cmd}")
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=60)
        if self.verbose and result.stdout:
            print(f"  [OUT] {result.stdout.strip()}")
        if check and result.returncode != 0:
            if self.verbose:
                print(f"  [ERR] Exit code {result.returncode}: {result.stderr}")
        return result.returncode, result.stdout, result.stderr

    def is_running(self) -> bool:
        result = subprocess.run(
            ["pgrep", "-x", "sysmon"],
            capture_output=True, text=True
        )
        return result.returncode == 0

    def apply_config(self, config_xml: str) -> bool:
        """Write and apply a Sysmon configuration via reinstall to clear event backlog."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".xml", delete=False) as f:
            f.write(config_xml)
            config_path = f.name

        try:
            # Use -u then -i to do a clean restart, clearing the eBPF ring buffer
            self.run_sysmon("-u force", check=False)
            time.sleep(2)
            rc, _, _ = self.run_sysmon(f"-i {config_path}", check=False)
            time.sleep(5)  # Allow sysmon to fully start and begin receiving events
            return rc == 0 and self.is_running()
        finally:
            os.unlink(config_path)

    def install(self, config_xml: Optional[str] = None) -> bool:
        """Install/reinstall sysmon with a config."""
        self.uninstall()
        time.sleep(1)

        if config_xml:
            with tempfile.NamedTemporaryFile(mode="w", suffix=".xml", delete=False) as f:
                f.write(config_xml)
                config_path = f.name
            try:
                rc, _, _ = self.run_sysmon(f"-i {config_path}", check=False)
            finally:
                os.unlink(config_path)
        else:
            rc, _, _ = self.run_sysmon("-i", check=False)

        time.sleep(3)
        return self.is_running()

    def uninstall(self) -> bool:
        if self.is_running():
            self.run_sysmon("-u", check=False)
            time.sleep(2)
        return not self.is_running()

    def restart_service(self):
        """Restart via systemd."""
        subprocess.run(["sudo", "systemctl", "restart", "sysmon"], timeout=30)
        time.sleep(3)

    def get_schema_version(self) -> str:
        rc, stdout, stderr = self.run_sysmon("-? config", check=False)
        combined = stdout + stderr
        m = re.search(r"schema is version:\s+([\d.]+)", combined)
        return m.group(1) if m else SCHEMA_VERSION


# ============================================================================
# Test Framework Base
# ============================================================================

@dataclass
class TestError:
    """Represents a test assertion failure."""
    module: str
    description: str

    def __str__(self):
        prefix = f"[{self.module}] " if self.module else ""
        return f"{prefix}{self.description}"


class TestResult:
    """Collects results from a test run."""
    def __init__(self, test_name: str):
        self.test_name = test_name
        self.errors: List[TestError] = []
        self.passed = True
        self.skipped = False
        self.skip_reason = ""
        self.start_time: Optional[datetime] = None
        self.end_time: Optional[datetime] = None

    @property
    def duration(self) -> float:
        if self.start_time and self.end_time:
            return (self.end_time - self.start_time).total_seconds()
        return 0.0

    def add_error(self, module: str, description: str, *args):
        if args:
            description = description.format(*args)
        self.errors.append(TestError(module, description))
        self.passed = False


class IntegrationTest:
    """
    Base class for integration tests. Mirrors UniTestTemplate from C#.

    Subclasses implement:
      - description: test purpose
      - get_config(): returns XML config for the test
      - trigger(): performs the action to generate events
      - validate(): checks events were generated correctly
    """

    def __init__(self, sysmon: SysmonManager, verbose: bool = False):
        self.sysmon = sysmon
        self.verbose = verbose
        self.schema_version = SCHEMA_VERSION
        self.result = TestResult(self.__class__.__name__)
        self.time_start: Optional[datetime] = None
        self.time_end: Optional[datetime] = None

    @property
    def description(self) -> str:
        return ""

    def get_config(self) -> Optional[str]:
        """Return XML config for this test, or None to use the default."""
        return None

    def prepare(self):
        """Called before trigger to set up the test environment."""
        pass

    def trigger(self):
        """Perform the action that should generate the event(s)."""
        pass

    def validate(self):
        """Validate that the expected events were generated."""
        pass

    def cleanup(self):
        """Clean up any resources created during the test."""
        pass

    def run(self) -> TestResult:
        """Execute the full test lifecycle."""
        self.result = TestResult(self.__class__.__name__)
        self.result.start_time = datetime.now(timezone.utc)

        if self.verbose:
            print(f"\n{'='*60}")
            print(f"TEST: {self.__class__.__name__}")
            print(f"  {self.description}")
            print(f"{'='*60}")

        try:
            # Apply config
            config = self.get_config()
            if config:
                if self.verbose:
                    print("  [SETUP] Applying test configuration...")
                if not self.sysmon.apply_config(config):
                    self.result.add_error("Setup", "Failed to apply configuration")
                    return self.result

            # Prepare
            self.prepare()

            # Record start time
            self.time_start = datetime.now(timezone.utc)
            time.sleep(1)

            # Trigger
            if self.verbose:
                print("  [TRIGGER] Executing test action...")
            self.trigger()
            time.sleep(2)

            # Record end time
            self.time_end = datetime.now(timezone.utc)

            # Validate
            if self.verbose:
                print("  [VALIDATE] Checking events...")
            self.validate()

        except Exception as e:
            self.result.add_error("Exception", str(e))
        finally:
            try:
                self.cleanup()
            except Exception:
                pass

        self.result.end_time = datetime.now(timezone.utc)

        if self.verbose:
            status = "PASSED" if self.result.passed else "FAILED"
            print(f"  [{status}] {self.__class__.__name__} ({self.result.duration:.1f}s)")
            for err in self.result.errors:
                print(f"    ERROR: {err}")

        return self.result

    # -- Assertion helpers (mirrors C# CheckCondition/CheckProperty) --

    def check_condition(self, condition: bool, module: str, description: str, *args) -> bool:
        if not condition:
            self.result.add_error(module, description, *args)
        return condition

    def check_property(self, entry: EventEntry, module: str, **expected) -> bool:
        """Check that event properties match expected regex patterns."""
        all_ok = True
        for prop_name, pattern in expected.items():
            value = entry.properties.get(prop_name, "")
            if not re.search(pattern, value, re.IGNORECASE):
                self.result.add_error(
                    module,
                    f"Property '{prop_name}' didn't match pattern '{pattern}' (actual: '{value}')"
                )
                all_ok = False
        return all_ok

    def check_property_exact(self, entry: EventEntry, module: str, **expected) -> bool:
        """Check that event properties match expected values exactly (case-insensitive)."""
        all_ok = True
        for prop_name, expected_val in expected.items():
            value = entry.properties.get(prop_name, "")
            if value.lower() != expected_val.lower():
                self.result.add_error(
                    module,
                    f"Property '{prop_name}' expected '{expected_val}' but got '{value}'"
                )
                all_ok = False
        return all_ok

    def find_events(self, event_id: int, filter_desc: FilterDesc,
                    wait_seconds: int = DEFAULT_WAIT_SECONDS,
                    expected_matches: int = 1) -> EventFilterResult:
        """Find events, using this test's time window."""
        return EventFilter.find_events(
            event_id, filter_desc,
            since_time=self.time_start,
            wait_seconds=wait_seconds,
            expected_matches=expected_matches
        )


# ============================================================================
# Utility Functions
# ============================================================================

def re_escape_full(s: str) -> str:
    """Escape for exact match regex."""
    return "^" + re.escape(s) + "$"


def re_escape_endwith(s: str) -> str:
    """Escape for ends-with match regex."""
    return "^.*" + re.escape(s) + "$"


def re_escape_contains(s: str) -> str:
    """Escape for contains match regex."""
    return re.escape(s)


def current_user() -> str:
    """Get the current user name."""
    return os.environ.get("USER", os.environ.get("LOGNAME", "root"))


def random_string(length: int = 12) -> str:
    """Generate a random alphanumeric string."""
    import random
    import string
    return ''.join(random.choices(string.ascii_lowercase + string.digits, k=length))


def sha256_file(filepath: str) -> str:
    """Compute SHA256 hash of a file."""
    import hashlib
    h = hashlib.sha256()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest().upper()


def sha1_file(filepath: str) -> str:
    """Compute SHA1 hash of a file."""
    import hashlib
    h = hashlib.sha1()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest().upper()


def make_config(event_filtering_body: str, hash_algorithms: str = "",
                extra_options: str = "") -> str:
    """Build a Sysmon configuration XML string."""
    hash_line = ""
    if hash_algorithms:
        hash_line = f"<HashAlgorithms>{hash_algorithms}</HashAlgorithms>"

    return f"""<Sysmon schemaversion="{SCHEMA_VERSION}">
{hash_line}
{extra_options}
<EventFiltering>
{event_filtering_body}
</EventFiltering>
</Sysmon>"""
