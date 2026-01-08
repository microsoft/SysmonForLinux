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
// sysmonBPFLoad_tp.c
//
// Traditional tracepoint program for eBPF load events.
//
//====================================================================

#include "sysmonEBPF_common.h"
#include <sysinternalsEBPF_helpers.c>
#include "sysmonHelpers.c"
#include "sysmonBPFLoad.c"


// sys_exit
SEC("tracepoint/syscalls/sys_exit_bpf")
__attribute__((flatten))
int BPFLoadExit(struct tracepoint__syscalls__sys_exit *args)
{
    uint64_t pidTid = bpf_get_current_pid_tgid();
    uint32_t cpuId = bpf_get_smp_processor_id();
    PSYSMON_EVENT_HEADER eventHdr = NULL;
    argsStruct *eventArgs = NULL;
    const ebpfConfig *config;
    char *ptr = NULL;

    if (!setUpEvent(&config, &eventArgs))
        return 0;

    // set the return code
    eventArgs->returnCode = args->ret;

    if (!getEventHdr(&eventHdr, cpuId))
        return 0;

    ptr = set_BPFLoad_info(eventHdr, config, pidTid, cpuId, eventArgs);
    if (ptr != NULL && ptr > (char *)eventHdr) {
        eventHdr->m_EventSize = (uint32_t)((void *)ptr - (void *)eventHdr);
        checkAndSendEvent((void *)args, eventHdr, config);
    }

    // Cleanup
    bpf_map_delete_elem(&argsHash, &pidTid);

    return 0;
}
