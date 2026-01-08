/*
    SysmonForLinux

    Copyright (c) Microsoft Corporation

    All rights reserved.

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License along
    with this program; if not, write to the Free Software Foundation, Inc.,
    51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
*/

//====================================================================
//
// sysmonBPFLoad.c
//
// Report eBPF program load events via the bpf() syscall.
// This event is Linux-only and detects when eBPF programs are loaded.
//
//====================================================================

#include "missingdefs.h"

// BPF commands from linux/bpf.h
#define BPF_MAP_CREATE          0
#define BPF_MAP_LOOKUP_ELEM     1
#define BPF_MAP_UPDATE_ELEM     2
#define BPF_MAP_DELETE_ELEM     3
#define BPF_MAP_GET_NEXT_KEY    4
#define BPF_PROG_LOAD           5
#define BPF_OBJ_PIN             6
#define BPF_OBJ_GET             7
#define BPF_PROG_ATTACH         8
#define BPF_PROG_DETACH         9
#define BPF_PROG_RUN            10
#define BPF_PROG_GET_NEXT_ID    11
#define BPF_MAP_GET_NEXT_ID     12
#define BPF_PROG_GET_FD_BY_ID   13
#define BPF_MAP_GET_FD_BY_ID    14
#define BPF_OBJ_GET_INFO_BY_FD  15

// BPF program types from linux/bpf.h
#define BPF_PROG_TYPE_UNSPEC            0
#define BPF_PROG_TYPE_SOCKET_FILTER     1
#define BPF_PROG_TYPE_KPROBE            2
#define BPF_PROG_TYPE_SCHED_CLS         3
#define BPF_PROG_TYPE_SCHED_ACT         4
#define BPF_PROG_TYPE_TRACEPOINT        5
#define BPF_PROG_TYPE_XDP               6
#define BPF_PROG_TYPE_PERF_EVENT        7
#define BPF_PROG_TYPE_CGROUP_SKB        8
#define BPF_PROG_TYPE_CGROUP_SOCK       9
#define BPF_PROG_TYPE_LWT_IN            10
#define BPF_PROG_TYPE_LWT_OUT           11
#define BPF_PROG_TYPE_LWT_XMIT          12
#define BPF_PROG_TYPE_SOCK_OPS          13
#define BPF_PROG_TYPE_SK_SKB            14
#define BPF_PROG_TYPE_CGROUP_DEVICE     15
#define BPF_PROG_TYPE_SK_MSG            16
#define BPF_PROG_TYPE_RAW_TRACEPOINT    17
#define BPF_PROG_TYPE_CGROUP_SOCK_ADDR  18
#define BPF_PROG_TYPE_LWT_SEG6LOCAL     19
#define BPF_PROG_TYPE_LIRC_MODE2        20
#define BPF_PROG_TYPE_SK_REUSEPORT      21
#define BPF_PROG_TYPE_FLOW_DISSECTOR    22
#define BPF_PROG_TYPE_CGROUP_SYSCTL     23
#define BPF_PROG_TYPE_RAW_TRACEPOINT_WRITABLE 24
#define BPF_PROG_TYPE_CGROUP_SOCKOPT    25
#define BPF_PROG_TYPE_TRACING           26
#define BPF_PROG_TYPE_STRUCT_OPS        27
#define BPF_PROG_TYPE_EXT               28
#define BPF_PROG_TYPE_LSM               29
#define BPF_PROG_TYPE_SK_LOOKUP         30
#define BPF_PROG_TYPE_SYSCALL           31

// Maximum length for BPF program name
#ifndef BPF_OBJ_NAME_LEN
#define BPF_OBJ_NAME_LEN 16
#endif

// BPF attr structure for PROG_LOAD command (from linux/bpf.h UAPI)
// This is a user-space structure passed to the bpf() syscall.
// Note: The bpf_attr union layout is defined in UAPI headers and is ABI-stable.
// For CO-RE, we define the relevant portion of the structure to enable
// proper field access even though UAPI structures don't typically relocate.
struct bpf_attr_prog_load {
    __u32 prog_type;
    __u32 insn_cnt;
    __u64 insns;
    __u64 license;
    __u32 log_level;
    __u32 log_size;
    __u64 log_buf;
    __u32 kern_version;
    __u32 prog_flags;
    char prog_name[BPF_OBJ_NAME_LEN];
    // Additional fields follow but are not needed
};

__attribute__((always_inline))
static inline char* set_BPFLoad_info(
    PSYSMON_EVENT_HEADER eventHdr,
    const ebpfConfig *config,
    uint64_t pidTid,
    uint32_t cpuId,
    const argsStruct *eventArgs
    )
{
    const void *task = NULL;
    char *ptr = NULL;
    uint64_t extLen = 0;
    int cmd = 0;
    uint32_t prog_type = 0;
    char prog_name[BPF_OBJ_NAME_LEN + 1];

    if (eventHdr == NULL || config == NULL || eventArgs == NULL)
        return (char *)eventHdr;

    // Get the BPF command from first argument
    cmd = (int)eventArgs->a[0];

    // Only monitor BPF_PROG_LOAD and BPF_PROG_ATTACH commands
    // These are the most security-relevant operations
    if (cmd != BPF_PROG_LOAD && cmd != BPF_PROG_ATTACH) {
        return (char *)eventHdr;
    }

    // For PROG_LOAD, the return value is the file descriptor (>=0 on success)
    // For PROG_ATTACH, return value is 0 on success
    if (cmd == BPF_PROG_LOAD && eventArgs->returnCode < 0) {
        return (char *)eventHdr;
    }
    if (cmd == BPF_PROG_ATTACH && eventArgs->returnCode != 0) {
        return (char *)eventHdr;
    }

    // get the task struct
    task = (const void *)bpf_get_current_task();
    if (!task)
        return (char *)eventHdr;

    // initialise event
    eventHdr->m_FieldFiltered = 0;
    eventHdr->m_PreFiltered = 0;
    eventHdr->m_SequenceNumber = 0;
    eventHdr->m_SessionId = 0;

    eventHdr->m_EventType = LinuxEBPFEvent;
    PSYSMON_LINUX_EBPF_EVENT event = (PSYSMON_LINUX_EBPF_EVENT)&eventHdr->m_EventBody;

    // set the pid
    event->m_ProcessId = pidTid >> 32;

    // set event time - this is in nanoseconds and we want 100ns intervals
    event->m_EventTime.QuadPart = (bpf_ktime_get_ns() + config->bootNsSinceEpoch) / 100;

    // set the BPF command
    event->m_BpfCmd = cmd;

    // Read program type and name from the bpf_attr union (second argument)
    // The bpf_attr is a UAPI structure passed from user space.
    // We use bpf_probe_read for user memory access.
    // For CO-RE builds, we use the defined structure for proper field offsets.

    if (cmd == BPF_PROG_LOAD) {
        const struct bpf_attr_prog_load *attr = 
            (const struct bpf_attr_prog_load *)eventArgs->a[1];
        if (attr != NULL) {
#ifdef EBPF_CO_RE
            // CO-RE: Use BPF_CORE_READ for proper field relocation
            // Note: bpf_attr is UAPI so offsets are stable, but this follows
            // the project's pattern for kernel structure access.
            bpf_probe_read_user(&prog_type, sizeof(prog_type), &attr->prog_type);
#else
            // Non-CO-RE: Read prog_type (first field in the union for PROG_LOAD)
            bpf_probe_read(&prog_type, sizeof(prog_type), attr);
#endif
            event->m_ProgType = prog_type;

            // For successful loads, return code is the FD
            event->m_ProgId = (ULONG)eventArgs->returnCode;
        }
    } else {
        event->m_ProgType = 0;
        event->m_ProgId = 0;
    }

    ptr = (char *)(event + 1);
    memset(event->m_Extensions, 0, sizeof(event->m_Extensions));

    // Insert the UID as the SID
    // Note: getUid() is CO-RE aware internally
    *(uint64_t *)ptr = getUid((struct task_struct*) task, config) & 0xFFFFFFFF;
    event->m_Extensions[LINUX_EBPF_Sid] = sizeof(uint64_t);
    ptr += sizeof(uint64_t);

    // Copy the executable path
    // Note: copyExePath() is CO-RE aware internally
    extLen = copyExePath(ptr, task, config);
    event->m_Extensions[LINUX_EBPF_ImagePath] = extLen;
    asm volatile("%[extLen] &= " XSTR(PATH_MAX - 1) "\n"
                 "%[ptr] += %[extLen]"
                 :[extLen]"+&r"(extLen), [ptr]"+&r"(ptr)
                 );

    // Read the program name from bpf_attr for BPF_PROG_LOAD commands
    memset(prog_name, 0, sizeof(prog_name));
    if (cmd == BPF_PROG_LOAD) {
        const struct bpf_attr_prog_load *attr = 
            (const struct bpf_attr_prog_load *)eventArgs->a[1];
        if (attr != NULL) {
#ifdef EBPF_CO_RE
            // CO-RE: Use bpf_probe_read_user for proper user memory access
            bpf_probe_read_user(prog_name, BPF_OBJ_NAME_LEN, &attr->prog_name);
#else
            // Non-CO-RE: Read prog_name at calculated offset
            // prog_type(4) + insn_cnt(4) + insns(8) + license(8) +
            // log_level(4) + log_size(4) + log_buf(8) + kern_version(4) + prog_flags(4) = 48
            bpf_probe_read(prog_name, BPF_OBJ_NAME_LEN, (const char *)attr + 48);
#endif
            prog_name[BPF_OBJ_NAME_LEN] = '\0';
        }
    }

    // Copy program name to extensions
    size_t name_len = 0;
    #pragma unroll
    for (int i = 0; i < BPF_OBJ_NAME_LEN; i++) {
        if (prog_name[i] == '\0') break;
        ptr[i] = prog_name[i];
        name_len++;
    }
    ptr[name_len] = '\0';
    event->m_Extensions[LINUX_EBPF_ProgName] = name_len + 1;
    ptr += name_len + 1;

    return ptr;
}
