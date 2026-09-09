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
// sysmonProcCreate.c
//
// Report process creation events as a result of execve()execveat().
//
//====================================================================

__attribute__((always_inline))
static inline char* set_process_ext(
    PSYSMON_PROCESS_CREATE event,
    const ebpfConfig *config,
    const void *task
    )
{

    char *ptr = NULL;
    uint64_t extLen = 0;

    ptr = (char *)(event + 1);
    memset(event->m_Extensions, 0, sizeof(event->m_Extensions));

    // Insert the UID as the SID
    *(uint64_t *)ptr = event->m_AuthenticationId.LowPart;
    event->m_Extensions[PC_Sid] = sizeof(uint64_t);
    ptr += sizeof(uint64_t);

    extLen = copyExePath(ptr, task, config);
    event->m_Extensions[PC_ImagePath] = extLen;

    // Following piece of asm is required because without it clang puts extLen
    // onto the stack after the first statement (bounding it with (PATH_MAX - 1))
    // and when it retrieves it, the verifier has forgotten that it was bounded.
    // The asm performs the equivalent of the following C statements, but by doing
    // it in asm, it magically happens all in registers without hitting the stack.
    //
    //    extLen &= (PATH_MAX -1);
    //    ptr += extLen;
    asm volatile("%[extLen] &= " XSTR(PATH_MAX - 1) "\n"
                 "%[ptr] += %[extLen]"
                 :[extLen]"+&r"(extLen), [ptr]"+&r"(ptr)
                 );

    extLen = copyCommandline(ptr, task, config);
    event->m_Extensions[PC_CommandLine] = extLen;
    asm volatile("%[extLen] &= " XSTR(CMDLINE_MAX_LEN - 1) "\n"
                 "%[ptr] += %[extLen]"
                 :[extLen]"+&r"(extLen), [ptr]"+&r"(ptr)
                 );

    extLen = copyPwdPath(ptr, task, config);
    event->m_Extensions[PC_CurrentDirectory] = extLen;
    asm volatile("%[extLen] &= " XSTR(PATH_MAX - 1) "\n"
                 "%[ptr] += %[extLen]"
                 :[extLen]"+&r"(extLen), [ptr]"+&r"(ptr)
                 );

    return ptr;
}

__attribute__((always_inline))
static inline char* set_ProcCreate_info(
    PSYSMON_EVENT_HEADER eventHdr,
    const ebpfConfig *config,
    uint64_t pidTid,
    uint32_t cpuId,
    const argsStruct *eventArgs
    )
{
    const void *task = NULL;
    const void *p_task = NULL;
    const void *cred = NULL;
    char *ptr = NULL;
    uint64_t extLen = 0;

    if (eventHdr == NULL || config == NULL || eventArgs == NULL)
        return (char *)eventHdr;

    // only record successful process creations
    if (eventArgs->returnCode != 0)
        return (char *)eventHdr;

    // get the task struct
    task = (const void *)bpf_get_current_task();
    if (!task)
        return (char *)eventHdr;

    // initialise event
    eventHdr->m_FieldFiltered = 0;
    eventHdr->m_PreFiltered = 0;
    eventHdr->m_SequenceNumber = 0;
    eventHdr->m_SessionId = 0;

    eventHdr->m_EventType = ProcessCreate;
    PSYSMON_PROCESS_CREATE event = &eventHdr->m_EventBody.m_ProcessCreateEvent;

    // set the pid
    event->m_ProcessId = pidTid >> 32;

    // set the process objects (task ptrs)
#ifdef EBPF_CO_RE
    p_task = BPF_CORE_READ((struct task_struct *)task, parent);
#else
    p_task = (const void *)derefPtr(task, config->offsets.parent);
#endif

    event->m_ProcessObject = (PVOID)task;
    event->m_ParentProcessObject = (PVOID)p_task;

    // get the ppid
#ifdef EBPF_CO_RE
    event->m_ParentProcessId = BPF_CORE_READ((struct task_struct *)p_task, pid);
#else
    event->m_ParentProcessId = (uint32_t)derefPtr(p_task, config->offsets.pid);
#endif

    // get the session
    if (config->offsets.auid[0] != -1) {
#ifdef EBPF_CO_RE
        event->m_AuditUserId = (ULONG) BPF_CORE_READ((struct task_struct *)task, loginuid.val);
        event->m_SessionId = BPF_CORE_READ((struct task_struct *)task, sessionid);;
#else
        event->m_AuditUserId = (uint32_t)derefPtr(task, config->offsets.auid);
        event->m_SessionId = (uint32_t)derefPtr(task, config->offsets.ses);
#endif
    } else {
        event->m_AuditUserId = -1;
        event->m_SessionId = -1;
    }

    // get the creds
#ifdef EBPF_CO_RE
    cred = BPF_CORE_READ((struct task_struct *)task, cred);
#else
    cred = (const void *)derefPtr(task, config->offsets.cred);
#endif
    if (cred) {
#ifdef EBPF_CO_RE
        event->m_AuthenticationId.LowPart = (DWORD) BPF_CORE_READ((struct task_struct *)task, cred, uid.val);
        event->m_AuthenticationId.HighPart = (DWORD) BPF_CORE_READ((struct task_struct *)task, signal, tty, index);
#else
        event->m_AuthenticationId.LowPart = (uint32_t)derefPtr(cred, config->offsets.cred_uid);
        event->m_AuthenticationId.HighPart = (uint32_t)derefPtr(task, config->offsets.tty);
#endif
    } else {
        BPF_PRINTK("ERROR, failed to deref creds\n");
        event->m_AuthenticationId.LowPart = -1;
        event->m_AuthenticationId.HighPart = -1;
    }

    // get the process key - this is the end of the text segment currently as it should be
    // a) randomised for a PIE executable; and
    // b) dependent on the amount of code in the process
#ifdef EBPF_CO_RE
    event->m_ProcessKey = BPF_CORE_READ((struct task_struct *)task, mm, end_code);
#else
    event->m_ProcessKey = (uint64_t)derefPtr(task, config->offsets.mm_end_code);
#endif

    // get process start time - this is in nanoseconds and we want 100ns intervals
#ifdef EBPF_CO_RE
    event->m_CreateTime.QuadPart = BPF_CORE_READ((struct task_struct *)task, start_time);
#else
    event->m_CreateTime.QuadPart = (derefPtr(task, config->offsets.start_time));
#endif
    event->m_CreateTime.QuadPart = (event->m_CreateTime.QuadPart + config->bootNsSinceEpoch) / 100;

    return set_process_ext(event, config, task);
}
