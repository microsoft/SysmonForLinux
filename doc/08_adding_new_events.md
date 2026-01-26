# Adding New Events to Sysmon for Linux

This guide provides a comprehensive, step-by-step walkthrough for adding new events to Sysmon for Linux.

## Table of Contents

1. [Overview](#overview)
2. [Architecture Understanding](#architecture-understanding)
3. [Step 1: Define the Event in manifest.xml](#step-1-define-the-event-in-manifestxml)
4. [Step 2: Define Data Structures in linuxTypes.h](#step-2-define-data-structures-in-linuxtypesh)
5. [Step 3: Create eBPF Kernel Programs](#step-3-create-ebpf-kernel-programs)
6. [Step 4: Register Syscall Handlers](#step-4-register-syscall-handlers)
7. [Step 5: Process Events in Userspace](#step-5-process-events-in-userspace)
8. [Step 6: Format Event Output](#step-6-format-event-output)
9. [Step 7: Enable Event via Configuration](#step-7-enable-event-via-configuration)
10. [Step 8: Build and Test](#step-8-build-and-test)

---

## Overview

Adding a new event to Sysmon for Linux requires modifications across multiple layers:

```
┌─────────────────────────────────────────────────────────────┐
│                      User Space                              │
│  ┌─────────────┐  ┌──────────────┐  ┌────────────────────┐ │
│  │ manifest.xml│  │eventsCommon. │  │ sysmonforlinux.c   │ │
│  │ (event def) │  │cpp (format)  │  │ (event dispatch)   │ │
│  └─────────────┘  └──────────────┘  └────────────────────┘ │
├─────────────────────────────────────────────────────────────┤
│                    Perf Ring Buffer                          │
├─────────────────────────────────────────────────────────────┤
│                      Kernel Space                            │
│  ┌─────────────────────────────────────────────────────────┐│
│  │              eBPF Programs (sysmon*_rawtp.c)            ││
│  │         Attached to syscall tracepoints                 ││
│  └─────────────────────────────────────────────────────────┘│
└─────────────────────────────────────────────────────────────┘
```

---

## Architecture Understanding

### Event Flow

1. **Syscall occurs** → eBPF program attached to tracepoint fires
2. **eBPF program** → Collects data, populates event structure, sends via perf buffer
3. **Userspace handler** → Receives event from perf buffer
4. **Event processing** → Transforms/enriches data if needed
5. **Event formatting** → Converts to XML for syslog output
6. **Rules engine** → Filters based on configuration

### Key Concepts

#### Synthetic Syscall Numbers
For events triggered by tracepoints (not syscalls), Sysmon uses synthetic syscall numbers defined in `linuxTypes.h`:

```c
#define __NR_NETWORK            400  // Network tracepoint events
#define __NR_PROCTERM           401  // Process termination
#define __NR_RAWACCESS          402  // Raw device access
#define __NR_CREATE             403  // File create events
```

These are NOT real syscall numbers - they're internal identifiers for the telemetry library.

#### Event Types
- **LinuxFileOpen**, **LinuxNetworkEvent**, **LinuxEBPFEvent** - Internal Linux event types (0xFF01, 0xFF02, 0xFF03)
- These get transformed to standard Sysmon event types before output

---

## Step 1: Define the Event in manifest.xml

Location: `sysmonCommon/manifest.xml`

### 1.1 Add Event Template

Find the `<templates>` section and add your event template:

```xml
<template tid="EbpfEventArgs">
    <data name="RuleName" inType="win:UnicodeString" outType="xs:string" />
    <data name="UtcTime" inType="win:UnicodeString" outType="xs:string" />
    <data name="ProcessGuid" inType="win:GUID" outType="xs:GUID" />
    <data name="ProcessId" inType="win:UInt32" outType="win:PID" />
    <data name="Image" inType="win:UnicodeString" outType="xs:string" />
    <data name="User" inType="win:UnicodeString" outType="xs:string" />
    <data name="BpfCommand" inType="win:UnicodeString" outType="xs:string" />
    <data name="BpfProgramType" inType="win:UnicodeString" outType="xs:string" />
    <data name="BpfProgramId" inType="win:UInt32" outType="xs:unsignedInt" />
    <data name="BpfProgramName" inType="win:UnicodeString" outType="xs:string" />
</template>
```

**Important**: The order of `<data>` elements defines the field order in output.

### 1.2 Add Event Definition

Find the `<events>` section and add your event:

```xml
<event symbol="SYSMONEVENT_EBPF_EVENT"
       template="EbpfEventArgs"
       value="100"
       version="5"
       level="win:Informational"
       task="SYSMONTASK_EBPF_EVENT"
       opcode="Info"
       channel="SYSMON_CHANNEL"
       message="$(string.SYSMONEVENT_EBPF_EVENT)"
       rulename="EbpfEvent"
       ifdef="__linux__" />
```

Key attributes:
- `value="100"` - The Event ID (must be unique)
- `rulename="EbpfEvent"` - Name used in configuration rules
- `ifdef="__linux__"` - Linux-only event (optional)

### 1.3 Add Task Definition

In the `<tasks>` section:

```xml
<task name="SYSMONTASK_EBPF_EVENT" value="100"
      message="$(string.SYSMONTASK_EBPF_EVENT)" />
```

### 1.4 Add String Resources

In the `<stringTable>` section:

```xml
<string id="SYSMONTASK_EBPF_EVENT" value="Ebpf Event (rule: EbpfEvent)" />
<string id="SYSMONEVENT_EBPF_EVENT"
        value="Ebpf Event: &#xD;&#xA;RuleName: %1&#xD;&#xA;UtcTime: %2&#xD;&#xA;..." />
```

### 1.5 Regenerate Headers

After modifying manifest.xml, regenerate the headers:

```bash
cd build
cmake ..   # This runs the T4 template processor
```

This generates:
- `sysmonevents.h` - Event structures and field enums
- `sysmonmsg.h` - Message definitions

---

## Step 2: Define Data Structures in linuxTypes.h

Location: `linuxTypes.h`

### 2.1 Define Internal Event Type

Add near other Linux event type definitions:

```c
#define LinuxEBPFEvent          0xFF03
```

### 2.2 Define Extension Enum

Extensions are variable-length fields that follow the fixed event structure:

```c
typedef enum {
    LINUX_EBPF_Sid,        // User ID (8 bytes)
    LINUX_EBPF_ImagePath,  // Process image path (string)
    LINUX_EBPF_ProgName,   // BPF program name (string)
    LINUX_EBPF_ExtMax
} LINUX_EBPF_Extensions;
```

### 2.3 Define Event Structure

```c
typedef struct {
    LARGE_INTEGER           m_EventTime;
    ULONG                   m_ProcessId;
    ULONG                   m_BpfCmd;       // BPF command (e.g., BPF_PROG_LOAD)
    ULONG                   m_ProgType;     // BPF program type
    ULONG                   m_ProgId;       // BPF program FD/ID
    ULONG                   m_Extensions[LINUX_EBPF_ExtMax];
} SYSMON_LINUX_EBPF_EVENT, *PSYSMON_LINUX_EBPF_EVENT;
```

**Critical**: The `m_Extensions` array stores the LENGTH of each variable-length field, NOT the data itself. Data follows the structure in memory.

### 2.4 Add to Event Body Union

In `SYSMON_EVENT_BODY`:

```c
typedef union _SYSMON_EVENT_BODY {
    // ... existing events ...
    SYSMON_LINUX_EBPF_EVENT         m_EBPFEvent;
} SYSMON_EVENT_BODY, *PSYSMON_EVENT_BODY;
```

---

## Step 3: Create eBPF Kernel Programs

### 3.1 Create Main Logic File

Location: `ebpfKern/sysmonBPFLoad.c`

```c
/*
    SysmonForLinux - sysmonBPFLoad.c

    eBPF program to monitor BPF syscall for program loads
*/

#include "sysmonEBPF_common.h"
#include <sysinternalsEBPFshared.h>

// Define constants if not available from system headers
#ifndef BPF_PROG_LOAD
#define BPF_PROG_LOAD           5
#endif

#ifndef BPF_PROG_ATTACH
#define BPF_PROG_ATTACH         8
#endif

// Program type definitions (from linux/bpf.h)
#define BPF_PROG_TYPE_UNSPEC            0
#define BPF_PROG_TYPE_SOCKET_FILTER     1
#define BPF_PROG_TYPE_KPROBE            2
// ... add all types you need

#ifndef BPF_OBJ_NAME_LEN
#define BPF_OBJ_NAME_LEN 16
#endif

__attribute__((always_inline))
static inline char* set_BPFLoad_info(
    PSYSMON_EVENT_HEADER eventHdr,
    const ebpfConfig *config,
    uint64_t pidTid,
    uint32_t cpuId,
    const argsStruct *eventArgs
    )
{
    // Get process info
    const void *task = (const void *)bpf_get_current_task();

    // Set event type
    eventHdr->m_EventType = LinuxEBPFEvent;

    PSYSMON_LINUX_EBPF_EVENT event =
        (PSYSMON_LINUX_EBPF_EVENT)&eventHdr->m_EventBody;
    char *ptr = (char *)(event + 1);  // Extensions follow the struct

    // Set timestamp
    event->m_EventTime.QuadPart =
        (config->bootNsSinceEpoch + bpf_ktime_get_ns()) / 100;

    // Set PID
    event->m_ProcessId = pidTid >> 32;

    // Get BPF command from syscall args
    uint32_t cmd = (uint32_t)eventArgs->a[0];
    event->m_BpfCmd = cmd;

    // Initialize extensions
    memset(event->m_Extensions, 0, sizeof(event->m_Extensions));

    // Extension 0: SID (User ID)
    if (ptr <= (char *)eventHdr + SYSMON_MAX_EVENT_SIZE - sizeof(uint64_t)) {
        *(uint64_t *)ptr = getUid(task);
        event->m_Extensions[LINUX_EBPF_Sid] = sizeof(uint64_t);
        ptr += sizeof(uint64_t);
    }

    // Extension 1: Image path
    ptr = copyExePath(ptr, task, &event->m_Extensions[LINUX_EBPF_ImagePath],
                      (char *)eventHdr + SYSMON_MAX_EVENT_SIZE);

    // Extension 2: Program name (for BPF_PROG_LOAD)
    if (cmd == BPF_PROG_LOAD) {
        // Get union bpf_attr pointer from syscall arg 1
        const void *attr = (const void *)eventArgs->a[1];

        // Get program type (offset 0 in bpf_attr for PROG_LOAD)
        uint32_t prog_type = 0;
        bpf_probe_read(&prog_type, sizeof(prog_type), attr);
        event->m_ProgType = prog_type;

        // Get program FD from return value
        event->m_ProgId = (uint32_t)eventArgs->returnCode;

        // Get program name (offset 48 in union bpf_attr for PROG_LOAD)
        char prog_name[BPF_OBJ_NAME_LEN + 1] = {};
        bpf_probe_read_str(prog_name, sizeof(prog_name), attr + 48);

        size_t name_len = 0;
        #pragma unroll
        for (int i = 0; i < BPF_OBJ_NAME_LEN; i++) {
            if (prog_name[i] == '\0') break;
            name_len++;
        }

        if (name_len > 0 && ptr + name_len + 1 <=
            (char *)eventHdr + SYSMON_MAX_EVENT_SIZE) {
            memcpy(ptr, prog_name, name_len);
            ptr[name_len] = '\0';
            event->m_Extensions[LINUX_EBPF_ProgName] = name_len + 1;
            ptr += name_len + 1;
        }
    }

    return ptr;
}
```

### 3.2 Create Raw Tracepoint Handler

Location: `ebpfKern/sysmonBPFLoad_rawtp.c`

```c
/*
    SysmonForLinux - sysmonBPFLoad_rawtp.c

    Raw tracepoint handler for BPF syscall (kernel 4.17+)
*/

#include "sysmonEBPF_common.h"
#include <sysinternalsEBPFshared.h>

// Include main logic
#include "sysmonBPFLoad.c"

SEC("raw_tracepoint/sys_exit")
int BPFLoadRawExit(struct bpf_our_raw_tracepoint_args *ctx)
{
    uint64_t pidTid = bpf_get_current_pid_tgid();
    uint32_t cpuId = bpf_get_smp_processor_id();

    argsStruct *eventArgs = bpf_map_lookup_elem(&argsHash, &pidTid);
    if (!eventArgs)
        return 0;

    // Only handle bpf syscall
    if (eventArgs->syscallId != __NR_bpf)
        return 0;

    // Get registers for return code
    struct pt_regs *regs = (struct pt_regs *)ctx->args[0];

    // Set return code
    if (bpf_probe_read(&eventArgs->returnCode, sizeof(int64_t),
                       (void *)&SYSCALL_PT_REGS_RC(regs)) != 0) {
        BPF_PRINTK("ERROR: failed to get return code for bpf syscall\n");
    }

    // Skip failed syscalls
    if (eventArgs->returnCode < 0) {
        bpf_map_delete_elem(&argsHash, &pidTid);
        return 0;
    }

    // Get BPF command
    uint32_t cmd = (uint32_t)eventArgs->a[0];

    // Only monitor BPF_PROG_LOAD and BPF_PROG_ATTACH
    if (cmd != BPF_PROG_LOAD && cmd != BPF_PROG_ATTACH) {
        bpf_map_delete_elem(&argsHash, &pidTid);
        return 0;
    }

    // Get config
    uint32_t configId = 0;
    ebpfConfig *config = bpf_map_lookup_elem(&configMap, &configId);
    if (!config) {
        bpf_map_delete_elem(&argsHash, &pidTid);
        return 0;
    }

    // Get event header
    PSYSMON_EVENT_HEADER eventHdr;
    if (!getEventHdr(&eventHdr, cpuId)) {
        bpf_map_delete_elem(&argsHash, &pidTid);
        return 0;
    }

    // Populate event
    char *ptr = set_BPFLoad_info(eventHdr, config, pidTid, cpuId, eventArgs);

    if (ptr != NULL && ptr > (char *)eventHdr) {
        eventHdr->m_EventSize = (uint32_t)((void *)ptr - (void *)eventHdr);
        checkAndSendEvent((void *)ctx, eventHdr, config);
    }

    // Cleanup
    bpf_map_delete_elem(&argsHash, &pidTid);
    return 0;
}
```

### 3.3 Create Tracepoint Handler (for older kernels)

Location: `ebpfKern/sysmonBPFLoad_tp.c`

```c
/*
    SysmonForLinux - sysmonBPFLoad_tp.c

    Traditional tracepoint handler for BPF syscall (kernel < 4.17)
*/

#include "sysmonEBPF_common.h"
#include <sysinternalsEBPFshared.h>

#include "sysmonBPFLoad.c"

SEC("tracepoint/syscalls/sys_exit_bpf")
int BPFLoadExit(struct tracepoint__syscalls__sys_exit *args)
{
    // Similar to raw tracepoint but uses args->ret directly
    // ...implementation similar to above...
}
```

### 3.4 Include in Kernel Objects

Add includes to each kernel version file:

`ebpfKern/sysmonEBPFkern4.15.c` and `sysmonEBPFkern4.16.c`:
```c
#include "sysmonBPFLoad_tp.c"
```

`ebpfKern/sysmonEBPFkern4.17-5.1.c`, `sysmonEBPFkern5.2.c`, `sysmonEBPFkern5.3-5.5.c`, `sysmonEBPFkern5.6-.c`:
```c
#include "sysmonBPFLoad_rawtp.c"
```

---

## Step 4: Register Syscall Handlers

Location: `sysmonforlinux.c`

### 4.1 Add to Tracepoint Program Arrays

For traditional tracepoints (kernel 4.15-4.16):
```c
const ebpfSyscallTPprog TPexitProgs[] = {
    // ... existing entries ...
    {__NR_bpf, "BPFLoadExit"}
};
```

For raw tracepoints (kernel 4.17+):
```c
const ebpfSyscallRTPprog RTPexitProgs[] = {
    // ... existing entries ...
    {"BPFLoadRawExit", __NR_bpf}
};
```

### 4.2 Add Syscall Activation

In `SetSyscallActive()`:
```c
void SetSyscallActive(bool *s, ULONG eventId)
{
    switch(eventId) {
        // ... existing cases ...

        case SYSMONEVENT_EBPF_EVENT_EVENT_value:
            s[__NR_bpf] = true;
            break;
    }
}
```

**Note**: Only use real syscall numbers here. Synthetic numbers (like `__NR_NETWORK`) are for tracepoint-based events that don't hook a specific syscall.

---

## Step 5: Process Events in Userspace

Location: `sysmonforlinux.c`

### 5.1 Add Event Handler Function

```c
//--------------------------------------------------------------------
//
// processEBPFEvent
//
// Handles eBPF program load events (Event ID 100)
//
//--------------------------------------------------------------------
void processEBPFEvent(CONST PSYSMON_EVENT_HEADER eventHdr)
{
    if (eventHdr == NULL) {
        fprintf(stderr, "processEBPFEvent invalid params\n");
        return;
    }

    // For simple events, just dispatch directly
    // For complex events, you might transform the data first
    DispatchEvent(eventHdr);
}
```

### 5.2 Add to Event Dispatcher

In `handleEvent()`:
```c
static void handleEvent(void *ctx, int cpu, void *data, uint32_t size)
{
    // ... validation code ...

    switch ((DWORD)eventHdr->m_EventType) {
        // ... existing cases ...

        case LinuxEBPFEvent:
            processEBPFEvent(eventHdr);
            break;

        default:
            DispatchEvent(eventHdr);
    }
}
```

---

## Step 6: Format Event Output

Location: `sysmonCommon/eventsCommon.cpp`

### 6.1 Add Event Formatting Case

In `EventWriteExt()`, find the switch statement for event types and add:

```cpp
#if defined(__linux__)
    // Handle Linux-specific event types
    if (eventHeader->m_EventType == LinuxEBPFEvent) {
        PSYSMON_LINUX_EBPF_EVENT ebpfEvent =
            &eventHeader->m_EventBody.m_EBPFEvent;
        const char *extPtr = (const char *)(ebpfEvent + 1);
        TCHAR userBuf[256];
        const char *bpfCmdStr = "UNKNOWN";
        const char *bpfProgTypeStr = "UNKNOWN";

        // Get BPF command name
        switch (ebpfEvent->m_BpfCmd) {
            case 0: bpfCmdStr = "BPF_MAP_CREATE"; break;
            case 1: bpfCmdStr = "BPF_MAP_LOOKUP_ELEM"; break;
            case 2: bpfCmdStr = "BPF_MAP_UPDATE_ELEM"; break;
            case 3: bpfCmdStr = "BPF_MAP_DELETE_ELEM"; break;
            case 4: bpfCmdStr = "BPF_MAP_GET_NEXT_KEY"; break;
            case 5: bpfCmdStr = "BPF_PROG_LOAD"; break;
            case 6: bpfCmdStr = "BPF_OBJ_PIN"; break;
            case 7: bpfCmdStr = "BPF_OBJ_GET"; break;
            case 8: bpfCmdStr = "BPF_PROG_ATTACH"; break;
            // ... add all commands up to latest kernel ...
            default: bpfCmdStr = "UNKNOWN"; break;
        }

        // Get BPF program type name
        switch (ebpfEvent->m_ProgType) {
            case 0: bpfProgTypeStr = "UNSPEC"; break;
            case 1: bpfProgTypeStr = "SOCKET_FILTER"; break;
            case 2: bpfProgTypeStr = "KPROBE"; break;
            case 3: bpfProgTypeStr = "SCHED_CLS"; break;
            // ... add all program types ...
            default: bpfProgTypeStr = "UNKNOWN"; break;
        }

        // Get User from SID extension
        const char *sidPtr = extPtr;
        extPtr += ebpfEvent->m_Extensions[LINUX_EBPF_Sid];
        uid_t uid = *(uint32_t *)sidPtr;
        struct passwd *pw = getpwuid(uid);
        if (pw) {
            _sntprintf(userBuf, _countof(userBuf), _T("%s"), pw->pw_name);
        } else {
            _sntprintf(userBuf, _countof(userBuf), _T("%d"), uid);
        }

        // Get Image path
        const char *imagePath = extPtr;
        extPtr += ebpfEvent->m_Extensions[LINUX_EBPF_ImagePath];

        // Get Program name
        const char *progName = extPtr;

        // Set all event fields
        EventSetFieldX(eventBuffer, F_EE_UtcTime, N_LargeTime,
                       ebpfEvent->m_EventTime);
        EventSetFieldX(eventBuffer, F_EE_ProcessGuid, N_ProcessId,
                       ebpfEvent->m_ProcessId);
        EventSetFieldX(eventBuffer, F_EE_ProcessId, N_ProcessId,
                       ebpfEvent->m_ProcessId);
        EventSetFieldS(eventBuffer, F_EE_Image, imagePath, FALSE);
        EventSetFieldS(eventBuffer, F_EE_User, userBuf, FALSE);
        EventSetFieldS(eventBuffer, F_EE_BpfCommand, bpfCmdStr, FALSE);
        EventSetFieldS(eventBuffer, F_EE_BpfProgramType, bpfProgTypeStr, FALSE);
        EventSetFieldX(eventBuffer, F_EE_BpfProgramId, N_Ulong,
                       ebpfEvent->m_ProgId);
        EventSetFieldS(eventBuffer, F_EE_BpfProgramName, progName, FALSE);

        EventProcess(&SYSMONEVENT_EBPF_EVENT_Type, eventBuffer,
                     eventHeader, NULL);
        break;
    }
#endif
```

**Important**: Field names like `F_EE_BpfCommand` are auto-generated from manifest.xml. The pattern is `F_<EVENT_ABBREV>_<FieldName>`.

---

## Step 7: Enable Event via Configuration

### 7.1 Default Event State

In `sysmonCommon/manifest.xml`, the `rulename` attribute controls if the event is included by default:

```xml
<event ... rulename="EbpfEvent" />
```

Events are **excluded by default** unless explicitly included in rules.

### 7.2 Configuration File Example

```xml
<Sysmon schemaversion="4.90">
  <EventFiltering>
    <!-- Include all eBPF events -->
    <RuleGroup name="EbpfEvents" groupRelation="or">
      <EbpfEvent onmatch="include">
        <BpfProgramName condition="is not">-</BpfProgramName>
      </EbpfEvent>
    </RuleGroup>

    <!-- Or exclude libbpf probes -->
    <RuleGroup name="EbpfFilter" groupRelation="or">
      <EbpfEvent onmatch="exclude">
        <BpfProgramName condition="begin with">libbpf_</BpfProgramName>
      </EbpfEvent>
    </RuleGroup>
  </EventFiltering>
</Sysmon>
```

---

## Step 8: Build and Test

### 8.1 Build

```bash
cd build
cmake ..
make
```

### 8.2 Install and Test

```bash
# Stop existing sysmon
sudo ./sysmon -u force

# Install with config
sudo ./sysmon -i /path/to/config.xml

# Watch logs
sudo tail -f /var/log/syslog | grep -i sysmon

# Trigger event (for eBPF event)
sudo bpftool prog load /tmp/test.o /sys/fs/bpf/test_prog
```

### 8.3 Validate with strace

```bash
sudo strace -e bpf bpftool prog load /tmp/test.o /sys/fs/bpf/test_prog
```

---

