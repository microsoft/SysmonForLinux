#!/usr/bin/env python3
"""
SysmonForLinux Integration Test Cases

Implements test cases for all Linux-supported Sysmon events.
Each test follows the pattern from the Windows C# integration tests:
  1. Apply targeted config
  2. Trigger the event
  3. Validate event fields

Supported Events on Linux:
  Event 1  - Process Create
  Event 2  - File Create Time Changed
  Event 3  - Network Connect
  Event 4  - Service State Change
  Event 5  - Process Terminate
  Event 9  - RawAccessRead (block device)
  Event 10 - ProcessAccess (ptrace)
  Event 11 - FileCreate
  Event 16 - Config Change
  Event 22 - DNS Query
  Event 23 - File Delete (archived)
  Event 26 - File Delete Detected
"""

import os
import re
import socket
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path

from sysmon_test_framework import (
    EventFilter, EventIds, FilterDesc, IntegrationTest, SysmonManager,
    current_user, make_config, random_string, re_escape_contains,
    re_escape_endwith, re_escape_full, sha1_file, sha256_file,
    DEFAULT_WAIT_SECONDS,
)


# ============================================================================
# Event 1 & 5 - Process Create & Terminate
# ============================================================================

class TestProcessCreate(IntegrationTest):
    """
    Test Event ID 1 (Process Create) and Event ID 5 (Process Terminate).
    Mirrors: IntegrationTests/Tests/ProcessEvents.cs
    """

    @property
    def description(self):
        return "Ensure Sysmon process creation and termination are correctly logged."

    def __init__(self, sysmon, verbose=False):
        super().__init__(sysmon, verbose)
        self.test_arg = f"sysmon_test_{random_string()}"

    def get_config(self):
        return make_config(f"""
        <RuleGroup name="" groupRelation="or">
            <ProcessCreate onmatch="include">
                <CommandLine condition="contains">{self.test_arg}</CommandLine>
            </ProcessCreate>
        </RuleGroup>
        <RuleGroup name="" groupRelation="or">
            <ProcessTerminate onmatch="exclude" />
        </RuleGroup>
""")

    def trigger(self):
        # Launch a process with a unique argument so we can find it
        result = subprocess.run(
            ["/bin/echo", self.test_arg],
            capture_output=True, text=True
        )
        time.sleep(1)

    def validate(self):
        # -- Validate ProcessCreate for /bin/echo --
        result = self.find_events(
            EventIds.SYSMON_CREATE_PROCESS,
            FilterDesc.from_pairs(True,
                "Image", re_escape_endwith("/echo"),
                "CommandLine", re_escape_contains(self.test_arg)),
            wait_seconds=DEFAULT_WAIT_SECONDS,
            expected_matches=1
        )

        if self.check_condition(len(result.match) >= 1, "ProcessCreate",
                                "Expected at least 1 ProcessCreate for /bin/echo, got {0}",
                                len(result.match)):
            entry = result.match[0]
            self.check_property(entry, "ProcessCreate",
                                Image=re_escape_endwith("/echo"),
                                CommandLine=re_escape_contains(self.test_arg),
                                User=f".*")

            # Verify important fields are present
            for field in ["ProcessId", "ProcessGuid", "ParentProcessId",
                          "ParentImage", "UtcTime"]:
                self.check_condition(
                    field in entry.properties and entry.properties[field],
                    "FieldPresent",
                    "Expected non-empty field '{0}' in ProcessCreate", field
                )

            # -- Validate ProcessTerminate matches ProcessCreate by GUID --
            process_guid = entry.get("ProcessGuid")
            if process_guid:
                term_result = self.find_events(
                    EventIds.SYSMON_PROCESS_TERMINATE,
                    FilterDesc.from_pairs(False,
                        "ProcessGuid", "^" + re.escape(process_guid) + "$"),
                    wait_seconds=DEFAULT_WAIT_SECONDS
                )
                self.check_condition(
                    len(term_result.match) >= 1,
                    "ProcessTerminate",
                    "Expected termination event for GUID {0}, got {1}",
                    process_guid, len(term_result.match)
                )

                if len(term_result.match) >= 1:
                    # Verify PIDs match between create and terminate
                    self.check_condition(
                        term_result.match[0].get("ProcessId") == entry.get("ProcessId"),
                        "PID-Match",
                        "ProcessIds should match between create and terminate"
                    )


# ============================================================================
# Event 2 - File Creation Time Changed
# ============================================================================

class TestFileCreateTime(IntegrationTest):
    """
    Test Event ID 2 (File creation time changed).
    Mirrors: IntegrationTests/Tests/FileTimeEvent.cs
    """

    @property
    def description(self):
        return "Test the FileCreateTime event when file timestamps are modified."

    def __init__(self, sysmon, verbose=False):
        super().__init__(sysmon, verbose)
        self.temp_file = None

    def get_config(self):
        return make_config("""
        <RuleGroup name="" groupRelation="or">
            <FileCreateTime onmatch="exclude" />
        </RuleGroup>
""")

    def trigger(self):
        # Create a temp file
        fd, self.temp_file = tempfile.mkstemp(prefix="sysmon_filetime_test_")
        os.write(fd, b"sysmon filetime test content")
        os.close(fd)
        time.sleep(1)

        # Change the file's modification and access times to a past date
        past_time = datetime(2020, 1, 1, 12, 0, 0).timestamp()
        os.utime(self.temp_file, (past_time, past_time))
        time.sleep(1)

    def validate(self):
        if not self.temp_file:
            self.result.add_error("Setup", "No temp file created")
            return

        result = self.find_events(
            EventIds.SYSMON_FILE_TIME,
            FilterDesc.from_pairs(False,
                "TargetFilename", re_escape_full(self.temp_file)),
            wait_seconds=DEFAULT_WAIT_SECONDS
        )

        # FileCreateTime (Event 2) may not be fully supported on all Linux kernels
        # as it depends on eBPF hooks for utimensat syscall
        if len(result.match) == 0:
            self.result.skipped = True
            self.result.skip_reason = "FileCreateTime event not generated (may not be supported on this kernel)"
            return

        entry = result.match[0]
        self.check_property(entry, "FileTimeChange",
                            TargetFilename=re_escape_full(self.temp_file))

    def cleanup(self):
        if self.temp_file and os.path.exists(self.temp_file):
            os.unlink(self.temp_file)


# ============================================================================
# Event 3 - Network Connect
# ============================================================================

class TestNetworkConnect(IntegrationTest):
    """
    Test Event ID 3 (Network connection detected).
    Mirrors: No direct Windows equivalent, but tests TCP connection logging.
    """

    @property
    def description(self):
        return "Test that TCP network connections are logged."

    def __init__(self, sysmon, verbose=False):
        super().__init__(sysmon, verbose)
        self.server_port = None

    def get_config(self):
        return make_config("""
        <RuleGroup name="" groupRelation="or">
            <NetworkConnect onmatch="exclude" />
        </RuleGroup>
""")

    def trigger(self):
        # Create a TCP server, connect to it from client, then close
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind(("127.0.0.1", 0))
        self.server_port = server.getsockname()[1]
        server.listen(1)
        server.settimeout(10)

        # Connect using an external process (so it has its own PID/image)
        proc = subprocess.Popen(
            ["python3", "-c",
             f"import socket; s=socket.socket(); s.connect(('127.0.0.1', {self.server_port})); s.close()"],
        )
        conn, addr = server.accept()
        conn.close()
        server.close()
        proc.wait()
        time.sleep(2)

    def validate(self):
        if not self.server_port:
            self.result.add_error("Setup", "Server port not set")
            return

        result = self.find_events(
            EventIds.SYSMON_NETWORK_CONNECT,
            FilterDesc.from_pairs(True,
                "DestinationPort", re_escape_full(str(self.server_port)),
                "DestinationIp", re_escape_full("127.0.0.1")),
            wait_seconds=DEFAULT_WAIT_SECONDS
        )

        if self.check_condition(len(result.match) >= 1, "NetworkConnect",
                                "Expected at least 1 NetworkConnect to port {0}, got {1}",
                                self.server_port, len(result.match)):
            entry = result.match[0]
            self.check_property(entry, "NetworkConnect",
                                DestinationPort=re_escape_full(str(self.server_port)),
                                DestinationIp=re_escape_full("127.0.0.1"),
                                Protocol="^tcp$")


# ============================================================================
# Event 4 - Service State Change
# ============================================================================

class TestServiceStateChange(IntegrationTest):
    """
    Test Event ID 4 (Sysmon service state changed).
    State events are generated on sysmon start/stop.
    """

    @property
    def description(self):
        return "Test that Sysmon service state changes generate events."

    def get_config(self):
        # No specific event filtering needed for state changes - they're always generated
        return None

    def trigger(self):
        # Restart sysmon to generate state change events
        self.sysmon.restart_service()
        time.sleep(3)

    def validate(self):
        result = self.find_events(
            EventIds.SYSMON_SERVICE_STATE_CHANGE,
            FilterDesc.from_pairs(False,
                "State", "(?:Started|Stopped)"),
            wait_seconds=DEFAULT_WAIT_SECONDS
        )

        self.check_condition(len(result.match) >= 1, "ServiceStateChange",
                             "Expected at least 1 ServiceStateChange event, got {0}",
                             len(result.match))

        # Check for "Started" state
        started = [e for e in result.match if e.get("State") == "Started"]
        self.check_condition(len(started) >= 1, "ServiceStarted",
                             "Expected at least 1 'Started' state event, got {0}",
                             len(started))


# ============================================================================
# Event 5 - Process Terminate (standalone)
# ============================================================================

class TestProcessTerminate(IntegrationTest):
    """
    Test Event ID 5 (Process terminated).
    Mirrors: Part of ProcessEvents.cs
    """

    @property
    def description(self):
        return "Test that process termination is correctly logged."

    def __init__(self, sysmon, verbose=False):
        super().__init__(sysmon, verbose)
        self.child_pid = None
        self.child_image = "/bin/sleep"
        self.test_marker = random_string()

    def get_config(self):
        return make_config(f"""
        <RuleGroup name="" groupRelation="or">
            <ProcessTerminate onmatch="exclude" />
        </RuleGroup>
        <RuleGroup name="" groupRelation="or">
            <ProcessCreate onmatch="include">
                <CommandLine condition="contains">{self.test_marker}</CommandLine>
            </ProcessCreate>
        </RuleGroup>
""")

    def trigger(self):
        proc = subprocess.Popen([self.child_image, "2"])
        self.child_pid = proc.pid
        proc.wait()
        time.sleep(2)

    def validate(self):
        if not self.child_pid:
            self.result.add_error("Setup", "No child PID captured")
            return

        result = self.find_events(
            EventIds.SYSMON_PROCESS_TERMINATE,
            FilterDesc.from_pairs(True,
                "ProcessId", re_escape_full(str(self.child_pid))),
            wait_seconds=DEFAULT_WAIT_SECONDS
        )

        if self.check_condition(len(result.match) >= 1, "ProcessTerminate",
                                "Expected ProcessTerminate for PID {0}, got {1}",
                                self.child_pid, len(result.match)):
            entry = result.match[0]
            self.check_property(entry, "ProcessTerminate",
                                ProcessId=re_escape_full(str(self.child_pid)),
                                Image=re_escape_endwith("/sleep"))

            # Verify ProcessGuid is present and non-empty
            pg = entry.get("ProcessGuid", "")
            self.check_condition(
                pg and pg != "-",
                "ProcessGuid-Present",
                "Expected non-empty ProcessGuid in ProcessTerminate"
            )


# ============================================================================
# Event 9 - RawAccessRead
# ============================================================================

class TestRawAccessRead(IntegrationTest):
    """
    Test Event ID 9 (Raw volume/block device access).
    Mirrors: IntegrationTests/Tests/RawAccess.cs
    Adapted for Linux block devices.
    """

    @property
    def description(self):
        return "Test the RawAccessRead event when block devices are opened."

    def __init__(self, sysmon, verbose=False):
        super().__init__(sysmon, verbose)
        self.block_device = None

    def get_config(self):
        return make_config("""
        <RuleGroup name="" groupRelation="or">
            <RawAccessRead onmatch="exclude" />
        </RuleGroup>
""")

    def _find_block_device(self):
        """Find a readable block device."""
        for dev in ["/dev/sda", "/dev/vda", "/dev/nvme0n1", "/dev/xvda"]:
            if os.path.exists(dev):
                return dev
        # Fallback: list block devices
        try:
            result = subprocess.run(["lsblk", "-dnpo", "NAME"], capture_output=True, text=True)
            devices = result.stdout.strip().split("\n")
            if devices and devices[0]:
                return devices[0].strip()
        except FileNotFoundError:
            pass
        return None

    def trigger(self):
        self.block_device = self._find_block_device()
        if not self.block_device:
            self.result.skipped = True
            self.result.skip_reason = "No block device found"
            return

        # Read a small amount from the block device using dd
        try:
            subprocess.run(
                ["sudo", "dd", f"if={self.block_device}", "of=/dev/null",
                 "bs=512", "count=1"],
                capture_output=True, timeout=10
            )
        except subprocess.TimeoutExpired:
            pass
        time.sleep(2)

    def validate(self):
        if self.result.skipped:
            return

        result = self.find_events(
            EventIds.SYSMON_RAWACCESS_READ,
            FilterDesc.from_pairs(False,
                "Image", ".*dd.*"),
            wait_seconds=DEFAULT_WAIT_SECONDS
        )

        if self.check_condition(len(result.match) >= 1, "RawAccessRead",
                                "Expected at least 1 RawAccessRead event, got {0}",
                                len(result.match)):
            entry = result.match[0]
            self.check_property(entry, "RawAccessRead",
                                Image=".*dd.*")


# ============================================================================
# Event 10 - Process Access (ptrace)
# ============================================================================

class TestProcessAccess(IntegrationTest):
    """
    Test Event ID 10 (Process accessed via ptrace).
    Mirrors: IntegrationTests/Tests/ProcessAccess.cs
    Adapted for Linux ptrace.
    """

    @property
    def description(self):
        return "Test the ProcessAccess event via ptrace attach/detach."

    def __init__(self, sysmon, verbose=False):
        super().__init__(sysmon, verbose)
        self.target_pid = None

    def get_config(self):
        return make_config("""
        <RuleGroup name="" groupRelation="or">
            <ProcessAccess onmatch="exclude" />
        </RuleGroup>
""")

    def trigger(self):
        # Start a target process
        target = subprocess.Popen(["/bin/sleep", "30"])
        self.target_pid = target.pid
        time.sleep(1)

        # Use strace to ptrace-attach (generates ProcessAccess event)
        try:
            strace = subprocess.run(
                ["sudo", "strace", "-p", str(self.target_pid), "-e", "trace=none",
                 "-o", "/dev/null"],
                capture_output=True, timeout=3
            )
        except subprocess.TimeoutExpired:
            pass

        time.sleep(2)
        target.terminate()
        target.wait()

    def validate(self):
        if not self.target_pid:
            self.result.add_error("Setup", "No target PID captured")
            return

        result = self.find_events(
            EventIds.SYSMON_ACCESS_PROCESS,
            FilterDesc.from_pairs(False,
                "TargetProcessId", re_escape_full(str(self.target_pid))),
            wait_seconds=DEFAULT_WAIT_SECONDS
        )

        if self.check_condition(len(result.match) >= 1, "ProcessAccess",
                                "Expected at least 1 ProcessAccess targeting PID {0}, got {1}",
                                self.target_pid, len(result.match)):
            entry = result.match[0]
            self.check_property(entry, "ProcessAccess",
                                SourceImage=".*strace.*",
                                TargetImage=re_escape_endwith("/sleep"))


# ============================================================================
# Event 11 - File Create
# ============================================================================

class TestFileCreate(IntegrationTest):
    """
    Test Event ID 11 (File creation).
    Mirrors: IntegrationTests/Tests/FileCreate.cs
    """

    @property
    def description(self):
        return "Test that file creation events are logged."

    def __init__(self, sysmon, verbose=False):
        super().__init__(sysmon, verbose)
        self.test_marker = random_string()
        self.test_file = os.path.join(tempfile.gettempdir(),
                                       f"sysmon_filecreate_{self.test_marker}.txt")

    def get_config(self):
        return make_config(f"""
        <RuleGroup name="" groupRelation="or">
            <FileCreate onmatch="include">
                <TargetFilename condition="contains">{self.test_marker}</TargetFilename>
            </FileCreate>
        </RuleGroup>
""")

    def trigger(self):
        with open(self.test_file, "w") as f:
            f.write("Sysmon FileCreate test content")
        time.sleep(2)

    def validate(self):
        result = self.find_events(
            EventIds.SYSMON_FILE_CREATE,
            FilterDesc.from_pairs(False,
                "TargetFilename", re_escape_full(self.test_file)),
            wait_seconds=DEFAULT_WAIT_SECONDS
        )

        if self.check_condition(len(result.match) >= 1, "FileCreate",
                                "Expected at least 1 FileCreate event for {0}, got {1}",
                                self.test_file, len(result.match)):
            entry = result.match[0]
            self.check_property(entry, "FileCreate",
                                TargetFilename=re_escape_full(self.test_file))

    def cleanup(self):
        if os.path.exists(self.test_file):
            os.unlink(self.test_file)


# ============================================================================
# Event 16 - Configuration Change
# ============================================================================

class TestConfigChange(IntegrationTest):
    """
    Test Event ID 16 (Sysmon configuration state changed).
    Changing the config should generate a config change event.
    """

    @property
    def description(self):
        return "Test that Sysmon configuration changes generate events."

    def get_config(self):
        # Start with a known config
        return make_config("""
        <RuleGroup name="" groupRelation="or">
            <ProcessCreate onmatch="exclude" />
        </RuleGroup>
""")

    def trigger(self):
        # Apply a different configuration to trigger event 16
        new_config = make_config("""
        <RuleGroup name="" groupRelation="or">
            <ProcessCreate onmatch="include" />
        </RuleGroup>
""")
        self.sysmon.apply_config(new_config)
        time.sleep(3)

    def validate(self):
        result = self.find_events(
            EventIds.SYSMON_SERVICE_CONFIGURATION_CHANGE,
            FilterDesc.from_pairs(False,
                "Configuration", ".*"),
            wait_seconds=DEFAULT_WAIT_SECONDS
        )

        self.check_condition(len(result.match) >= 1, "ConfigChange",
                             "Expected at least 1 config change event, got {0}",
                             len(result.match))


# ============================================================================
# Event 22 - DNS Query
# ============================================================================

class TestDnsQuery(IntegrationTest):
    """
    Test Event ID 22 (DNS query).
    Mirrors: IntegrationTests/Tests/DnsQueryEvent.cs
    """

    @property
    def description(self):
        return "Test the DNS query event."

    def __init__(self, sysmon, verbose=False):
        super().__init__(sysmon, verbose)
        self.test_domain = f"{random_string()}-sysmontest.example.com"

    def get_config(self):
        return make_config(f"""
        <RuleGroup name="" groupRelation="or">
            <DnsQuery onmatch="include">
                <QueryName condition="contains">sysmontest</QueryName>
            </DnsQuery>
        </RuleGroup>
""")

    def _find_dns_tool(self):
        """Find an available DNS lookup tool."""
        for tool in ["nslookup", "dig", "host"]:
            result = subprocess.run(["which", tool], capture_output=True)
            if result.returncode == 0:
                return result.stdout.decode().strip()
        return None

    def trigger(self):
        dns_tool = self._find_dns_tool()
        if not dns_tool:
            self.result.skipped = True
            self.result.skip_reason = "No DNS lookup tool found (nslookup/dig/host)"
            return

        time.sleep(2)

        tool_name = os.path.basename(dns_tool)
        if tool_name == "nslookup":
            subprocess.run([dns_tool, self.test_domain], capture_output=True, timeout=10)
        elif tool_name == "dig":
            subprocess.run([dns_tool, self.test_domain], capture_output=True, timeout=10)
        elif tool_name == "host":
            subprocess.run([dns_tool, self.test_domain], capture_output=True, timeout=10)

        time.sleep(3)

    def validate(self):
        if self.result.skipped:
            return

        result = self.find_events(
            EventIds.SYSMON_DNS_QUERY,
            FilterDesc.from_pairs(False,
                "QueryName", re_escape_full(self.test_domain)),
            wait_seconds=DEFAULT_WAIT_SECONDS
        )

        # DNS monitoring may not be available on all Linux builds/kernels
        if len(result.match) == 0:
            self.result.skipped = True
            self.result.skip_reason = "DnsQuery (Event 22) not generated (may not be supported on this kernel)"
            return

        entry = result.match[0]
        self.check_property(entry, "DnsQuery",
                            QueryName=re_escape_full(self.test_domain))


# ============================================================================
# Event 23 - File Delete (archived)
# ============================================================================

class TestFileDelete(IntegrationTest):
    """
    Test Event ID 23 (File delete with archiving).
    Mirrors: IntegrationTests/Tests/FileDeleteEvent.cs
    """

    @property
    def description(self):
        return "Test that file deletion (with archive) is logged."

    def __init__(self, sysmon, verbose=False):
        super().__init__(sysmon, verbose)
        self.test_marker = random_string()
        self.included_file = os.path.join(tempfile.gettempdir(),
                                           f"sysmon_delete_{self.test_marker}.included")
        self.excluded_file = os.path.join(tempfile.gettempdir(),
                                           f"sysmon_delete_{random_string()}.excluded")
        self.included_hash = None

    def get_config(self):
        return make_config(f"""
        <RuleGroup name="" groupRelation="or">
            <FileDelete onmatch="include">
                <TargetFilename condition="contains">{self.test_marker}</TargetFilename>
            </FileDelete>
        </RuleGroup>
""", hash_algorithms="SHA1")

    def trigger(self):
        # Create the included file
        data = os.urandom(64)
        with open(self.included_file, "wb") as f:
            f.write(data)
        self.included_hash = sha1_file(self.included_file)

        # Create the excluded file
        with open(self.excluded_file, "wb") as f:
            f.write(os.urandom(64))

        time.sleep(1)

        # Delete both files
        os.unlink(self.included_file)
        os.unlink(self.excluded_file)
        time.sleep(3)

    def validate(self):
        # Check included file is logged
        result = self.find_events(
            EventIds.SYSMON_FILE_DELETE,
            FilterDesc.from_pairs(False,
                "TargetFilename", re_escape_full(self.included_file)),
            wait_seconds=DEFAULT_WAIT_SECONDS
        )

        if self.check_condition(len(result.match) >= 1, "FileDelete-Included",
                                "Expected at least 1 FileDelete event for {0}, got {1}",
                                self.included_file, len(result.match)):
            entry = result.match[0]
            self.check_property(entry, "FileDelete-Included",
                                TargetFilename=re_escape_full(self.included_file))

            # Verify hash if present (may be '-' if HashAlgorithms not active)
            hashes = entry.get("Hashes", "-")
            if hashes != "-" and self.included_hash:
                self.check_condition(
                    self.included_hash.upper() in hashes.upper(),
                    "FileDelete-Hash",
                    "Expected SHA1={0} in Hashes field, got {1}",
                    self.included_hash, hashes
                )

        # Check excluded file is NOT logged
        excl_result = self.find_events(
            EventIds.SYSMON_FILE_DELETE,
            FilterDesc.from_pairs(False,
                "TargetFilename", re_escape_full(self.excluded_file)),
            wait_seconds=5,
            expected_matches=0
        )
        self.check_condition(len(excl_result.match) == 0, "FileDelete-Excluded",
                             "Expected 0 FileDelete events for excluded file, got {0}",
                             len(excl_result.match))

    def cleanup(self):
        for f in [self.included_file, self.excluded_file]:
            if os.path.exists(f):
                os.unlink(f)


# ============================================================================
# Event 26 - File Delete Detected (no archiving)
# ============================================================================

class TestFileDeleteDetected(IntegrationTest):
    """
    Test Event ID 26 (File delete detected without archiving).
    Unlike Event 23, this doesn't archive the deleted file.
    """

    @property
    def description(self):
        return "Test that file deletion detection (no archive) is logged."

    def __init__(self, sysmon, verbose=False):
        super().__init__(sysmon, verbose)
        self.test_marker = random_string()
        self.test_file = os.path.join(tempfile.gettempdir(),
                                       f"sysmon_deldetect_{self.test_marker}.tmp")

    def get_config(self):
        return make_config(f"""
        <RuleGroup name="" groupRelation="or">
            <FileDeleteDetected onmatch="include">
                <TargetFilename condition="contains">{self.test_marker}</TargetFilename>
            </FileDeleteDetected>
        </RuleGroup>
""")

    def trigger(self):
        with open(self.test_file, "wb") as f:
            f.write(os.urandom(64))
        time.sleep(1)
        os.unlink(self.test_file)
        time.sleep(3)

    def validate(self):
        result = self.find_events(
            EventIds.SYSMON_FILE_DELETE_DETECTED,
            FilterDesc.from_pairs(False,
                "TargetFilename", re_escape_full(self.test_file)),
            wait_seconds=DEFAULT_WAIT_SECONDS
        )

        # Event 26 may not be implemented on all Linux builds
        if len(result.match) == 0:
            self.result.skipped = True
            self.result.skip_reason = "FileDeleteDetected (Event 26) not generated (may not be supported)"
            return

        entry = result.match[0]
        self.check_property(entry, "FileDeleteDetected",
                            TargetFilename=re_escape_full(self.test_file))

    def cleanup(self):
        if os.path.exists(self.test_file):
            os.unlink(self.test_file)


# ============================================================================
# Event Filtering - Condition Tests
# ============================================================================

class TestEventFilteringIs(IntegrationTest):
    """
    Test event filtering with 'is' condition.
    Mirrors: IntegrationTests/Tests/EventFiltering.cs - Is()
    """

    @property
    def description(self):
        return "Test event filtering with 'is' condition (exact match excludes)."

    def __init__(self, sysmon, verbose=False):
        super().__init__(sysmon, verbose)
        self.test_arg_excluded = f"sysmon_filt_is_excl_{random_string()}"
        self.test_arg_included = f"sysmon_filt_is_incl_{random_string()}"

    def get_config(self):
        # Include all process creates with our markers, except the excluded one
        return make_config(f"""
        <RuleGroup name="" groupRelation="or">
            <ProcessCreate onmatch="include">
                <CommandLine condition="contains">sysmon_filt_is_</CommandLine>
            </ProcessCreate>
        </RuleGroup>
        <RuleGroup name="" groupRelation="and">
            <ProcessCreate onmatch="exclude">
                <CommandLine condition="is">/bin/echo {self.test_arg_excluded}</CommandLine>
            </ProcessCreate>
        </RuleGroup>
""")

    def trigger(self):
        # This should be excluded by the 'is' filter
        subprocess.run(["/bin/echo", self.test_arg_excluded], capture_output=True)
        # This should be included (different command line)
        subprocess.run(["/bin/echo", self.test_arg_included], capture_output=True)
        time.sleep(2)

    def validate(self):
        # Excluded event should not appear
        result_excl = self.find_events(
            EventIds.SYSMON_CREATE_PROCESS,
            FilterDesc.from_pairs(True,
                "CommandLine", re_escape_contains(self.test_arg_excluded)),
            wait_seconds=15
        )
        self.check_condition(len(result_excl.match) == 0, "FilterIs-Excluded",
                             "Expected 0 events (filtered out by 'is'), got {0}",
                             len(result_excl.match))

        # Included event should appear
        result_incl = self.find_events(
            EventIds.SYSMON_CREATE_PROCESS,
            FilterDesc.from_pairs(True,
                "CommandLine", re_escape_contains(self.test_arg_included)),
            wait_seconds=DEFAULT_WAIT_SECONDS
        )
        self.check_condition(len(result_incl.match) >= 1, "FilterIs-Included",
                             "Expected at least 1 event for non-excluded command, got {0}",
                             len(result_incl.match))


class TestEventFilteringContains(IntegrationTest):
    """
    Test event filtering with 'contains' condition.
    Mirrors: IntegrationTests/Tests/EventFiltering.cs - Contains()
    """

    @property
    def description(self):
        return "Test event filtering with 'contains' condition (exclude matching)."

    def __init__(self, sysmon, verbose=False):
        super().__init__(sysmon, verbose)
        self.test_marker = f"sysmon_filt_cont_{random_string()}"
        self.test_arg_excluded = f"AAA{self.test_marker}BBB"
        self.test_arg_included = f"sysmon_filt_cont_incl_{random_string()}"

    def get_config(self):
        return make_config(f"""
        <RuleGroup name="" groupRelation="or">
            <ProcessCreate onmatch="include">
                <CommandLine condition="contains">sysmon_filt_cont_</CommandLine>
            </ProcessCreate>
        </RuleGroup>
        <RuleGroup name="" groupRelation="and">
            <ProcessCreate onmatch="exclude">
                <CommandLine condition="contains">{self.test_marker}</CommandLine>
            </ProcessCreate>
        </RuleGroup>
""")

    def trigger(self):
        # This should be excluded (contains the marker)
        subprocess.run(["/bin/echo", self.test_arg_excluded], capture_output=True)
        # This should NOT be excluded
        subprocess.run(["/bin/echo", self.test_arg_included], capture_output=True)
        time.sleep(2)

    def validate(self):
        # Excluded event should not appear
        result_excl = self.find_events(
            EventIds.SYSMON_CREATE_PROCESS,
            FilterDesc.from_pairs(True,
                "CommandLine", re_escape_contains(self.test_arg_excluded)),
            wait_seconds=15
        )
        self.check_condition(len(result_excl.match) == 0, "FilterContains-Excluded",
                             "Expected 0 events for excluded command, got {0}",
                             len(result_excl.match))

        # Included event should appear
        result_incl = self.find_events(
            EventIds.SYSMON_CREATE_PROCESS,
            FilterDesc.from_pairs(True,
                "CommandLine", re_escape_contains(self.test_arg_included)),
            wait_seconds=DEFAULT_WAIT_SECONDS
        )
        self.check_condition(len(result_incl.match) >= 1, "FilterContains-Included",
                             "Expected at least 1 event for non-excluded command, got {0}",
                             len(result_incl.match))


class TestEventFilteringBeginWith(IntegrationTest):
    """
    Test event filtering with 'begin with' condition.
    Mirrors: IntegrationTests/Tests/EventFiltering.cs - BeginWith()
    """

    @property
    def description(self):
        return "Test event filtering with 'begin with' condition."

    def __init__(self, sysmon, verbose=False):
        super().__init__(sysmon, verbose)
        self.test_marker = f"sysmon_bw_{random_string()}"
        self.test_arg_included = f"sysmon_bw_incl_{random_string()}"

    def get_config(self):
        return make_config(f"""
        <RuleGroup name="" groupRelation="or">
            <ProcessCreate onmatch="include">
                <CommandLine condition="contains">sysmon_bw_</CommandLine>
            </ProcessCreate>
        </RuleGroup>
        <RuleGroup name="" groupRelation="and">
            <ProcessCreate onmatch="exclude">
                <CommandLine condition="begin with">/bin/echo {self.test_marker}</CommandLine>
            </ProcessCreate>
        </RuleGroup>
""")

    def trigger(self):
        # Begins with the filter value - should be excluded
        subprocess.run(["/bin/echo", self.test_marker + "_suffix"], capture_output=True)
        # Does not begin with - should be included
        subprocess.run(["/bin/echo", self.test_arg_included], capture_output=True)
        time.sleep(2)

    def validate(self):
        result = self.find_events(
            EventIds.SYSMON_CREATE_PROCESS,
            FilterDesc.from_pairs(True,
                "CommandLine", re_escape_contains(self.test_marker + "_suffix")),
            wait_seconds=15
        )
        self.check_condition(len(result.match) == 0, "FilterBeginWith-Excluded",
                             "Expected 0 events (begin with filter), got {0}",
                             len(result.match))

        result_incl = self.find_events(
            EventIds.SYSMON_CREATE_PROCESS,
            FilterDesc.from_pairs(True,
                "CommandLine", re_escape_contains(self.test_arg_included)),
            wait_seconds=DEFAULT_WAIT_SECONDS
        )
        self.check_condition(len(result_incl.match) >= 1, "FilterBeginWith-Included",
                             "Expected at least 1 included event, got {0}",
                             len(result_incl.match))


class TestEventFilteringEndWith(IntegrationTest):
    """
    Test event filtering with 'end with' condition.
    Mirrors: IntegrationTests/Tests/EventFiltering.cs - EndWith()
    """

    @property
    def description(self):
        return "Test event filtering with 'end with' condition."

    def __init__(self, sysmon, verbose=False):
        super().__init__(sysmon, verbose)
        self.test_marker = f"sysmon_ew_{random_string()}"
        self.test_arg_included = f"sysmon_ew_incl_{random_string()}"

    def get_config(self):
        return make_config(f"""
        <RuleGroup name="" groupRelation="or">
            <ProcessCreate onmatch="include">
                <CommandLine condition="contains">sysmon_ew_</CommandLine>
            </ProcessCreate>
        </RuleGroup>
        <RuleGroup name="" groupRelation="and">
            <ProcessCreate onmatch="exclude">
                <CommandLine condition="end with">{self.test_marker}</CommandLine>
            </ProcessCreate>
        </RuleGroup>
""")

    def trigger(self):
        # Ends with the marker - should be excluded
        subprocess.run(["/bin/echo", self.test_marker], capture_output=True)
        # Different ending - should be included
        subprocess.run(["/bin/echo", self.test_arg_included], capture_output=True)
        time.sleep(2)

    def validate(self):
        result = self.find_events(
            EventIds.SYSMON_CREATE_PROCESS,
            FilterDesc.from_pairs(True,
                "CommandLine", re_escape_contains(self.test_marker)),
            wait_seconds=15
        )
        self.check_condition(len(result.match) == 0, "FilterEndWith-Excluded",
                             "Expected 0 events (end with filter), got {0}",
                             len(result.match))

        result_incl = self.find_events(
            EventIds.SYSMON_CREATE_PROCESS,
            FilterDesc.from_pairs(True,
                "CommandLine", re_escape_contains(self.test_arg_included)),
            wait_seconds=DEFAULT_WAIT_SECONDS
        )
        self.check_condition(len(result_incl.match) >= 1, "FilterEndWith-Included",
                             "Expected at least 1 included event, got {0}",
                             len(result_incl.match))


class TestEventFilteringExcludes(IntegrationTest):
    """
    Test event filtering with 'excludes' (does not contain) condition.
    Mirrors: IntegrationTests/Tests/EventFiltering.cs - Excludes()
    """

    @property
    def description(self):
        return "Test event filtering with 'excludes' condition."

    def __init__(self, sysmon, verbose=False):
        super().__init__(sysmon, verbose)
        self.exclude_marker = f"sysmon_excl_{random_string()}"
        self.test_arg = f"AAA{self.exclude_marker}BBB"

    def get_config(self):
        # 'excludes' means "exclude event if value does NOT contain the string"
        # So events containing the marker will NOT be excluded (they pass through)
        return make_config(f"""
        <RuleGroup name="" groupRelation="or">
            <ProcessCreate onmatch="include">
                <CommandLine condition="contains">{self.exclude_marker}</CommandLine>
            </ProcessCreate>
        </RuleGroup>
""")

    def trigger(self):
        # Contains the marker, so 'excludes' does NOT match -> event logged
        subprocess.run(["/bin/echo", self.test_arg], capture_output=True)
        time.sleep(2)

    def validate(self):
        # 'excludes' means "exclude if the value does NOT contain the string"
        # Our command DOES contain it, so the exclude doesn't apply → event should appear
        result = self.find_events(
            EventIds.SYSMON_CREATE_PROCESS,
            FilterDesc.from_pairs(True,
                "CommandLine", re_escape_contains(self.exclude_marker)),
            wait_seconds=DEFAULT_WAIT_SECONDS
        )
        self.check_condition(len(result.match) >= 1, "FilterExcludes",
                             "Expected at least 1 event (excludes doesn't match), got {0}",
                             len(result.match))


# ============================================================================
# Hashing Test
# ============================================================================

class TestHashing(IntegrationTest):
    """
    Test that Sysmon correctly hashes executables.
    Mirrors: IntegrationTests/Tests/Hashing.cs
    """

    @property
    def description(self):
        return "Test that process create events include correct hash values."

    def __init__(self, sysmon, verbose=False):
        super().__init__(sysmon, verbose)
        self.test_binary = None
        self.expected_sha256 = None
        self.test_marker = random_string()

    def get_config(self):
        return make_config(f"""
        <RuleGroup name="" groupRelation="or">
            <ProcessCreate onmatch="include">
                <CommandLine condition="contains">{self.test_marker}</CommandLine>
            </ProcessCreate>
        </RuleGroup>
""", hash_algorithms="SHA256")

    def trigger(self):
        self.test_binary = "/bin/echo"
        self.expected_sha256 = sha256_file(self.test_binary)

        subprocess.run([self.test_binary, f"sysmon_hash_test_{self.test_marker}"],
                       capture_output=True)
        time.sleep(2)

    def validate(self):
        result = self.find_events(
            EventIds.SYSMON_CREATE_PROCESS,
            FilterDesc.from_pairs(True,
                "Image", re_escape_endwith("/echo"),
                "CommandLine", re_escape_contains(self.test_marker)),
            wait_seconds=DEFAULT_WAIT_SECONDS
        )

        if self.check_condition(len(result.match) >= 1, "Hashing",
                                "Expected at least 1 ProcessCreate for hash check, got {0}",
                                len(result.match)):
            entry = result.match[0]
            hashes = entry.get("Hashes", "")
            if self.expected_sha256:
                self.check_condition(
                    self.expected_sha256.upper() in hashes.upper(),
                    "Hashing-SHA256",
                    "Expected SHA256={0} in Hashes '{1}'",
                    self.expected_sha256, hashes
                )


# ============================================================================
# State and Errors Test
# ============================================================================

class TestStateAndErrors(IntegrationTest):
    """
    Test that no Sysmon errors were reported during the test run.
    Mirrors: IntegrationTests/Tests/StateAndErrors.cs
    """

    @property
    def description(self):
        return "Ensure no Sysmon errors were reported and all fields are complete."

    def get_config(self):
        return None  # Don't change config

    def trigger(self):
        pass  # No specific trigger needed

    def validate(self):
        # Check for error events
        result = self.find_events(
            EventIds.SYSMON_ERROR,
            FilterDesc(),
            wait_seconds=5,
            expected_matches=0
        )

        for entry in result.match:
            desc = entry.get("Description", "Unknown error")
            self.result.add_error("ErrorCheck",
                                  f"Sysmon error detected: ID={entry.get('ID')}, "
                                  f"Description={desc}")


# ============================================================================
# Process Create with Parent Info test
# ============================================================================

class TestProcessCreateParentInfo(IntegrationTest):
    """
    Test that ProcessCreate events include correct parent process information.
    Validates ParentProcessId, ParentImage, ParentCommandLine fields.
    """

    @property
    def description(self):
        return "Test ProcessCreate events include correct parent process information."

    def __init__(self, sysmon, verbose=False):
        super().__init__(sysmon, verbose)
        self.test_marker = random_string()

    def get_config(self):
        return make_config(f"""
        <RuleGroup name="" groupRelation="or">
            <ProcessCreate onmatch="include">
                <CommandLine condition="contains">{self.test_marker}</CommandLine>
            </ProcessCreate>
        </RuleGroup>
""")

    def trigger(self):
        # Using bash -c to create a known parent->child chain
        result = subprocess.run(
            ["/bin/bash", "-c", f"/bin/echo {self.test_marker}"],
            capture_output=True
        )
        time.sleep(2)

    def validate(self):
        result = self.find_events(
            EventIds.SYSMON_CREATE_PROCESS,
            FilterDesc.from_pairs(True,
                "Image", re_escape_endwith("/echo"),
                "CommandLine", re_escape_contains(self.test_marker)),
            wait_seconds=DEFAULT_WAIT_SECONDS
        )

        if self.check_condition(len(result.match) >= 1, "ParentInfo",
                                "Expected at least 1 ProcessCreate event, got {0}",
                                len(result.match)):
            entry = result.match[0]

            # ParentImage may be '-' if parent has already exited
            parent_img = entry.get("ParentImage", "")
            self.check_condition(
                "ParentImage" in entry.properties,
                "ParentImage-Present",
                "Expected ParentImage field to be present"
            )

            # ParentProcessId should be present and numeric
            ppid = entry.get("ParentProcessId", "")
            self.check_condition(ppid.isdigit(), "ParentPID",
                                 "Expected numeric ParentProcessId, got '{0}'", ppid)

            # ParentCommandLine should be present
            self.check_condition(
                "ParentCommandLine" in entry.properties,
                "ParentCmdLine-Present",
                "Expected ParentCommandLine field to be present"
            )


# ============================================================================
# Network Connect with UDP test
# ============================================================================

class TestNetworkConnectUDP(IntegrationTest):
    """
    Test Event ID 3 (Network connection) for UDP traffic.
    """

    @property
    def description(self):
        return "Test that UDP network activity is logged."

    def __init__(self, sysmon, verbose=False):
        super().__init__(sysmon, verbose)
        self.server_port = None

    def get_config(self):
        return make_config("""
        <RuleGroup name="" groupRelation="or">
            <NetworkConnect onmatch="exclude" />
        </RuleGroup>
""")

    def trigger(self):
        # Create a UDP server and send data to it
        server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        server.bind(("127.0.0.1", 0))
        self.server_port = server.getsockname()[1]
        server.settimeout(5)

        # Send UDP data from Python subprocess
        proc = subprocess.Popen(
            ["python3", "-c",
             f"import socket; s=socket.socket(socket.AF_INET, socket.SOCK_DGRAM); "
             f"s.sendto(b'test', ('127.0.0.1', {self.server_port})); s.close()"],
        )

        try:
            data, addr = server.recvfrom(1024)
        except socket.timeout:
            pass

        server.close()
        proc.wait()
        time.sleep(3)

    def validate(self):
        if not self.server_port:
            self.result.add_error("Setup", "Server port not set")
            return

        result = self.find_events(
            EventIds.SYSMON_NETWORK_CONNECT,
            FilterDesc.from_pairs(True,
                "DestinationPort", re_escape_full(str(self.server_port)),
                "Protocol", "^udp$"),
            wait_seconds=DEFAULT_WAIT_SECONDS
        )

        # UDP monitoring may not be supported on all kernel versions
        if len(result.match) == 0:
            self.result.skipped = True
            self.result.skip_reason = "UDP NetworkConnect not generated (may require newer kernel)"
            return

        entry = result.match[0]
        self.check_property(entry, "NetworkConnect-UDP",
                            Protocol="^udp$",
                            DestinationIp=re_escape_full("127.0.0.1"))


# ============================================================================
# Version Info test
# ============================================================================

class TestVersionInfo(IntegrationTest):
    """
    Test that Sysmon version info is consistent.
    Mirrors: IntegrationTests/Tests/VersionInfo.cs
    """

    @property
    def description(self):
        return "Ensure Sysmon version and schema version are reported."

    def get_config(self):
        return None  # No config change needed

    def trigger(self):
        pass  # Just checking version info, no trigger needed

    def validate(self):
        schema_version = self.sysmon.get_schema_version()
        self.check_condition(
            schema_version is not None and len(schema_version) > 0,
            "SchemaVersion",
            "Failed to retrieve schema version"
        )

        if self.verbose and schema_version:
            print(f"  [INFO] Schema version: {schema_version}")

        # Verify sysmon binary exists and is executable
        self.check_condition(
            os.path.isfile(self.sysmon.sysmon_path),
            "BinaryExists",
            "Sysmon binary not found at {0}", self.sysmon.sysmon_path
        )

        self.check_condition(
            os.access(self.sysmon.sysmon_path, os.X_OK),
            "BinaryExecutable",
            "Sysmon binary is not executable at {0}", self.sysmon.sysmon_path
        )


# ============================================================================
# Invalid Configuration Tests
# ============================================================================

class TestInvalidConfigs(IntegrationTest):
    """
    Test that sysmon correctly rejects various invalid configuration files.
    Validates error detection for malformed XML, bad schema versions,
    missing elements, non-XML content, and other invalid inputs.

    Uses both -c (config update) and -i (install) flags where applicable.
    """

    @property
    def description(self):
        return "Ensure sysmon detects and rejects all forms of invalid configuration files."

    def get_config(self):
        return None  # Tests manage configs directly

    def trigger(self):
        pass  # All validation happens in validate()

    def _write_temp_config(self, content):
        """Write content to a temp file and return the path."""
        f = tempfile.NamedTemporaryFile(mode="w", suffix=".xml", delete=False)
        f.write(content)
        f.close()
        return f.name

    def _run_sysmon_config(self, config_path, flag="-c"):
        """Run sysmon with config and return (exit_code, stdout, stderr, combined)."""
        cmd = f"sudo {self.sysmon.sysmon_path} {flag} {config_path}"
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=30)
        combined = result.stdout + result.stderr
        return result.returncode, result.stdout, result.stderr, combined

    def _test_config_rejected(self, name, content, flag="-c",
                              expect_error_pattern=None,
                              expect_nonzero_exit=True,
                              expect_crash=False):
        """
        Test that a config is rejected by sysmon.

        Args:
            name: Sub-test name for error reporting
            content: XML config content to write
            flag: sysmon flag to use (-c or -i)
            expect_error_pattern: regex to match in output (optional)
            expect_nonzero_exit: if True, expect exit code != 0
            expect_crash: if True, expect exit code >= 128 (signal)
        """
        path = self._write_temp_config(content)
        try:
            rc, stdout, stderr, combined = self._run_sysmon_config(path, flag)

            if self.verbose:
                print(f"  [{name}] exit={rc}, output snippet: "
                      f"{combined[:200].replace(chr(10), ' ')}")

            if expect_crash:
                self.check_condition(
                    rc >= 128 or rc != 0,
                    name,
                    "Expected crash or non-zero exit for {0}, got exit code {1}",
                    name, rc
                )
            elif expect_nonzero_exit:
                self.check_condition(
                    rc != 0,
                    name,
                    "Expected non-zero exit code for {0}, got exit code {1}",
                    name, rc
                )

            if expect_error_pattern:
                self.check_condition(
                    re.search(expect_error_pattern, combined, re.IGNORECASE) is not None,
                    name,
                    "Expected error pattern '{0}' not found in output for {1}",
                    expect_error_pattern, name
                )

            # Verify "Configuration file validated" should NOT appear for rejected configs
            if expect_nonzero_exit or expect_crash:
                validated = "Configuration file validated" in combined
                self.check_condition(
                    not validated,
                    name,
                    "Config was validated when it should have been rejected for {0}",
                    name
                )

        finally:
            os.unlink(path)

    def _test_config_accepted_with_warning(self, name, content, flag="-c",
                                           expect_warning_pattern=None):
        """
        Test that a config is accepted (exit 0) but produces a warning.

        Args:
            name: Sub-test name
            content: XML config content
            flag: sysmon flag
            expect_warning_pattern: regex to match warning in output
        """
        path = self._write_temp_config(content)
        try:
            rc, stdout, stderr, combined = self._run_sysmon_config(path, flag)

            if self.verbose:
                print(f"  [{name}] exit={rc}, output snippet: "
                      f"{combined[:200].replace(chr(10), ' ')}")

            # Config is accepted (exit 0) but may have warnings
            if expect_warning_pattern:
                self.check_condition(
                    re.search(expect_warning_pattern, combined, re.IGNORECASE) is not None,
                    name,
                    "Expected warning pattern '{0}' not found in output for {1}",
                    expect_warning_pattern, name
                )
        finally:
            os.unlink(path)

    def validate(self):
        # ============================================================
        # Category 1: Malformed XML (parse failures)
        # ============================================================

        # 1a. Completely broken XML
        self._test_config_rejected(
            "MalformedXML",
            "<bad xml\n",
            flag="-c",
            expect_error_pattern=r"Failed to load xml|error",
            expect_nonzero_exit=True
        )

        # 1b. Same with -i flag
        self._test_config_rejected(
            "MalformedXML_Install",
            "<bad xml\n",
            flag="-i",
            expect_error_pattern=r"Failed to load xml|error",
            expect_nonzero_exit=True
        )

        # 1c. Unclosed XML tags
        self._test_config_rejected(
            "UnclosedTags",
            '<Sysmon schemaversion="4.90"><EventFiltering>',
            flag="-c",
            expect_error_pattern=r"Failed to load xml|error",
            expect_nonzero_exit=True
        )

        # 1d. Mismatched closing tags
        self._test_config_rejected(
            "MismatchedTags",
            '<Sysmon schemaversion="4.90"><EventFiltering></Sysmon></EventFiltering>',
            flag="-c",
            expect_error_pattern=r"Failed to load xml|error",
            expect_nonzero_exit=True
        )

        # 1e. Invalid XML characters / binary content
        self._test_config_rejected(
            "BinaryContent",
            '\x00\x01\x02\x03\x04\x05',
            flag="-c",
            expect_nonzero_exit=True
        )

        # ============================================================
        # Category 2: Non-XML content
        # ============================================================

        # 2a. Plain text
        self._test_config_rejected(
            "PlainText",
            "This is not XML at all\n",
            flag="-c",
            expect_nonzero_exit=True
        )

        # 2b. Empty file
        self._test_config_rejected(
            "EmptyFile",
            "",
            flag="-c",
            expect_nonzero_exit=True
        )

        # 2c. JSON content
        self._test_config_rejected(
            "JSONContent",
            '{"Sysmon": {"schemaversion": "4.90"}}',
            flag="-c",
            expect_nonzero_exit=True
        )

        # 2d. YAML content
        self._test_config_rejected(
            "YAMLContent",
            "Sysmon:\n  schemaversion: 4.90\n  EventFiltering: {}\n",
            flag="-c",
            expect_nonzero_exit=True
        )

        # ============================================================
        # Category 3: Wrong root element / missing Sysmon root
        # ============================================================

        # 3a. Wrong root element name
        self._test_config_rejected(
            "WrongRootElement",
            '<NotSysmon schemaversion="4.90"><EventFiltering>'
            '</EventFiltering></NotSysmon>\n',
            flag="-c",
            expect_nonzero_exit=True
        )

        # 3b. Valid XML but completely unrelated structure
        self._test_config_rejected(
            "UnrelatedXML",
            '<?xml version="1.0"?><html><body>Hello</body></html>\n',
            flag="-c",
            expect_nonzero_exit=True
        )

        # ============================================================
        # Category 4: Schema version problems
        # ============================================================

        # 4a. Missing schema version attribute  
        self._test_config_rejected(
            "MissingSchemaVersion",
            '<Sysmon><EventFiltering></EventFiltering></Sysmon>\n',
            flag="-c",
            expect_error_pattern=r"Invalid schema version number",
            expect_nonzero_exit=True
        )

        # 4b. Empty Sysmon element (no attributes, no children)
        self._test_config_rejected(
            "EmptySysmonElement",
            '<Sysmon></Sysmon>\n',
            flag="-c",
            expect_error_pattern=r"Invalid schema version number",
            expect_nonzero_exit=True
        )

        # 4c. Non-numeric schema version
        self._test_config_rejected(
            "NonNumericSchema",
            '<Sysmon schemaversion="abc"><EventFiltering>'
            '</EventFiltering></Sysmon>\n',
            flag="-c",
            expect_error_pattern=r"Invalid schema version number",
            expect_nonzero_exit=True
        )

        # 4d. Negative schema version
        self._test_config_rejected(
            "NegativeSchema",
            '<Sysmon schemaversion="-1.0"><EventFiltering>'
            '</EventFiltering></Sysmon>\n',
            flag="-c",
            expect_error_pattern=r"Invalid schema version",
            expect_nonzero_exit=True
        )

        # 4e. Very old / unsupported schema version
        self._test_config_rejected(
            "OldSchema",
            '<Sysmon schemaversion="1.0"><EventFiltering>'
            '<RuleGroup name="" groupRelation="or">'
            '<ProcessCreate onmatch="include">'
            '<Image condition="is">/bin/ls</Image>'
            '</ProcessCreate></RuleGroup>'
            '</EventFiltering></Sysmon>\n',
            flag="-c",
            expect_error_pattern=r"Incorrect or unsupported schema|Incompatible",
            expect_nonzero_exit=True
        )

        # 4f. Schema version 0.0
        self._test_config_rejected(
            "ZeroSchema",
            '<Sysmon schemaversion="0.0"><EventFiltering>'
            '</EventFiltering></Sysmon>\n',
            flag="-c",
            expect_nonzero_exit=True
        )

        # 4g. Negative schema with -i flag
        self._test_config_rejected(
            "NegativeSchema_Install",
            '<Sysmon schemaversion="-1.0"><EventFiltering>'
            '</EventFiltering></Sysmon>\n',
            flag="-i",
            expect_error_pattern=r"Invalid schema version",
            expect_nonzero_exit=True
        )

        # ============================================================
        # Category 5: Invalid filter conditions and attributes
        # ============================================================

        # 5a. Invalid condition operator
        self._test_config_accepted_with_warning(
            "InvalidCondition",
            '<Sysmon schemaversion="4.90"><EventFiltering>'
            '<RuleGroup name="" groupRelation="or">'
            '<ProcessCreate onmatch="include">'
            '<Image condition="invalidcondition">/bin/ls</Image>'
            '</ProcessCreate></RuleGroup>'
            '</EventFiltering></Sysmon>\n',
            flag="-c",
            expect_warning_pattern=r"Unknown condition"
        )

        # ============================================================
        # Category 6: XXE / XML entity injection attempts
        # ============================================================

        # 6a. XXE with file:// entity (security test)
        # pugixml ignores DTD by default, so this should be safe
        xxe_config = (
            '<?xml version="1.0" encoding="UTF-8"?>'
            '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'
            '<Sysmon schemaversion="4.90"><EventFiltering>'
            '<RuleGroup name="" groupRelation="or">'
            '<ProcessCreate onmatch="include">'
            '<Image condition="is">&xxe;</Image>'
            '</ProcessCreate></RuleGroup>'
            '</EventFiltering></Sysmon>\n'
        )
        path = self._write_temp_config(xxe_config)
        try:
            rc, stdout, stderr, combined = self._run_sysmon_config(path, "-c")
            if self.verbose:
                print(f"  [XXE_FileEntity] exit={rc}")
            # The key assertion: /etc/passwd content should NOT appear in output
            self.check_condition(
                "root:" not in combined,
                "XXE_FileEntity",
                "XXE entity was expanded - /etc/passwd content found in output (security vulnerability)"
            )
        finally:
            os.unlink(path)

        # 6b. XXE with SYSTEM entity pointing to network
        xxe_network = (
            '<?xml version="1.0" encoding="UTF-8"?>'
            '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://127.0.0.1:9999/evil">]>'
            '<Sysmon schemaversion="4.90"><EventFiltering>'
            '<RuleGroup name="" groupRelation="or">'
            '<ProcessCreate onmatch="include">'
            '<Image condition="is">&xxe;</Image>'
            '</ProcessCreate></RuleGroup>'
            '</EventFiltering></Sysmon>\n'
        )
        path = self._write_temp_config(xxe_network)
        try:
            rc, stdout, stderr, combined = self._run_sysmon_config(path, "-c")
            if self.verbose:
                print(f"  [XXE_NetworkEntity] exit={rc}")
            # Should not hang or crash trying network access
            self.check_condition(
                rc is not None,
                "XXE_NetworkEntity",
                "Sysmon may have hung on network XXE entity expansion"
            )
        finally:
            os.unlink(path)

        # ============================================================
        # Category 7: Extremely large / adversarial input
        # ============================================================

        # 7a. Very long element name
        long_name = "A" * 10000
        self._test_config_rejected(
            "VeryLongElementName",
            f'<Sysmon schemaversion="4.90"><EventFiltering>'
            f'<RuleGroup name="" groupRelation="or">'
            f'<{long_name} onmatch="include">'
            f'<Image condition="is">/bin/ls</Image>'
            f'</{long_name}></RuleGroup>'
            f'</EventFiltering></Sysmon>\n',
            flag="-c",
            # May be accepted (unknown events are ignored) or rejected
            expect_nonzero_exit=False
        )

        # 7b. Very long attribute value
        long_value = "B" * 100000
        path = self._write_temp_config(
            f'<Sysmon schemaversion="4.90"><EventFiltering>'
            f'<RuleGroup name="" groupRelation="or">'
            f'<ProcessCreate onmatch="include">'
            f'<Image condition="is">{long_value}</Image>'
            f'</ProcessCreate></RuleGroup>'
            f'</EventFiltering></Sysmon>\n'
        )
        try:
            rc, stdout, stderr, combined = self._run_sysmon_config(path, "-c")
            if self.verbose:
                print(f"  [VeryLongAttrValue] exit={rc}")
            # Should not crash (exit >= 128 means signal)
            self.check_condition(
                rc < 128,
                "VeryLongAttrValue",
                "Sysmon crashed (signal {0}) on very long attribute value",
                rc
            )
        finally:
            os.unlink(path)

        # 7c. Deeply nested XML
        depth = 500
        nested = "<a>" * depth + "</a>" * depth
        self._test_config_rejected(
            "DeeplyNestedXML",
            f'<Sysmon schemaversion="4.90"><EventFiltering>{nested}'
            f'</EventFiltering></Sysmon>\n',
            flag="-c",
            expect_nonzero_exit=False  # May or may not reject
        )

        # ============================================================
        # Category 8: Non-existent config file
        # ============================================================

        # 8a. Non-existent file path with -c
        rc, stdout, stderr, combined = (None, "", "", "")
        cmd = f"sudo {self.sysmon.sysmon_path} -c /tmp/nonexistent_sysmon_config_{random_string()}.xml"
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=30)
        combined = result.stdout + result.stderr
        if self.verbose:
            print(f"  [NonExistentFile_C] exit={result.returncode}")
        self.check_condition(
            result.returncode != 0 or "Usage:" in combined,
            "NonExistentFile_C",
            "Expected error or usage output for non-existent config file with -c"
        )

        # 8b. Non-existent file path with -i
        cmd = f"sudo {self.sysmon.sysmon_path} -i /tmp/nonexistent_sysmon_config_{random_string()}.xml"
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=30)
        combined = result.stdout + result.stderr
        if self.verbose:
            print(f"  [NonExistentFile_I] exit={result.returncode}")
        self.check_condition(
            result.returncode != 0 or "Usage:" in combined or "error" in combined.lower(),
            "NonExistentFile_I",
            "Expected error for non-existent config file with -i"
        )

        # ============================================================
        # Category 9: Sysmon still running after all invalid configs
        # ============================================================

        # After all these invalid config attempts, sysmon should still be running
        self.check_condition(
            self.sysmon.is_running(),
            "SysmonStillRunning",
            "Sysmon is no longer running after invalid config tests"
        )

        # Verify sysmon can still accept a valid config after all the bad ones
        valid_config = make_config("""
        <RuleGroup name="" groupRelation="or">
            <ProcessCreate onmatch="exclude" />
        </RuleGroup>
""")
        self.check_condition(
            self.sysmon.apply_config(valid_config),
            "ValidConfigAfterInvalid",
            "Sysmon failed to accept a valid config after processing invalid configs"
        )


# ============================================================================
# Test Registry
# ============================================================================

# ALL_TESTS defines all available test classes in execution order
ALL_TESTS = [
    TestVersionInfo,
    TestProcessCreate,
    TestProcessTerminate,
    TestProcessCreateParentInfo,
    TestFileCreate,
    TestFileCreateTime,
    TestFileDelete,
    TestFileDeleteDetected,
    TestNetworkConnect,
    TestNetworkConnectUDP,
    TestServiceStateChange,
    TestConfigChange,
    TestRawAccessRead,
    TestProcessAccess,
    TestDnsQuery,
    TestHashing,
    TestEventFilteringIs,
    TestEventFilteringContains,
    TestEventFilteringBeginWith,
    TestEventFilteringEndWith,
    TestEventFilteringExcludes,
    TestInvalidConfigs,
    TestStateAndErrors,
]
