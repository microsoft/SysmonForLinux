/*
    SysmonForLinux

    Copyright (c) Microsoft Corporation

    All rights reserved.

    MIT License

    Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the ""Software""), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED *AS IS*, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

//====================================================================
//
// SysmonForLinux.c
//
// Implements the main function and event handler for Sysmon For
// Linux.
//
//====================================================================

#include <libxml/parser.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <sys/types.h>
#include <linux/stat.h>
#include <fcntl.h>
#include <string.h>
#include <time.h>
#include <math.h>
#include <syslog.h>
#include <signal.h>
#include <semaphore.h>
#include <dirent.h>
#include <sys/mman.h>
#include <asm/unistd.h>
#include <dlfcn.h>
#include <libsysinternalsEBPF.h>
#include <sysinternalsEBPFshared.h>
#include "stdafx.h"
#include "rules.h"
#include "xml.h"
#include "linuxHelpers.h"
#include "sysmon_defs.h"
#include "linuxVersion.h"
#include "networkTracker.h"
#include "installer.h"

#include "missingdefs.h"

#define EVENT_BUFFER_SIZE (49 * 1024)

#define BTF_KERNEL_FILE "/sys/kernel/btf/vmlinux"

#define STARTUP_SEM_NAME "/sysmon-startup"

unsigned long           totalEvents = 0;
unsigned long           badEvents = 0;
unsigned int            numLostNotifications = 0;
unsigned long           numLostEvents = 0;

PTCHAR                  configFile = NULL;
sem_t                   *startupSem = NULL;

struct NetworkTracker   *NetworkState;
int                     eventIdFd = 0;
uint64_t                *eventIdAddr = MAP_FAILED;

double                  g_bootSecSinceEpoch = 0;
BOOLEAN                 g_DebugMode = FALSE;
BOOLEAN                 g_DebugModeVerbose = FALSE;
CRITICAL_SECTION        g_DebugModePrintCriticalSection;
char*                   btfPath;

typedef TCHAR _bstr_t;

bool CreateNetworkEvent( DWORD processId, DWORD threadId, EVENT_TYPE_NETWORK type, bool isTcp,
                        LARGE_INTEGER timestamp, ULONGLONG duration, DWORD length,
                        bool srcIsIpV4, const BYTE * srcAddr, WORD srcPort,
                        bool dstIsIpV4, const BYTE * dstAddr, WORD dstPort,
                        const void * const stackEntries[], DWORD stackCnt,
                        const _bstr_t *details );

//--------------------------------------------------------------------
//
// const EBPF Config
//
//--------------------------------------------------------------------

const char                      *defPaths[] =
    {"./", "./sysmonEBPF", "/opt/sysmon/", "/opt/sysmon/sysmonEBPF"};

const ebpfSyscallTPprog         TPenterProgs[] =
{   {EBPF_GENERIC_SYSCALL, "genericEnterN"}
};

const ebpfSyscallTPprog         TPexitProgs[] =
{   {__NR_execve, "ProcCreateExit"},
    {__NR_execveat, "ProcCreateExit"},
    {__NR_creat, "FileCreateExit"},
    {__NR_open, "FileOpenExit"},
    {__NR_openat, "FileOpenExit"},
    {__NR_unlink, "FileDeleteExit"},
    {__NR_unlinkat, "FileDeleteAtExit"},
    {__NR_unlinkat, "FileDeleteAtCwdExit"},
    {__NR_accept, "TCPacceptExit"},
    {__NR_accept4, "TCPacceptExit"},
    {__NR_ptrace, "ProcAccessedExit"},
    {__NR_recvfrom, "UDPrecvExit"},
    {__NR_recvmsg, "UDPrecvExit"},
    {__NR_recvmmsg, "UDPrecvExit"},
    {__NR_read, "UDPrecvExit"},
    {__NR_close, "CloseFDExit"}
};

const ebpfSyscallRTPprog        RTPenterProgs[] =
{
    {"genericRawEnter", EBPF_GENERIC_SYSCALL}
};

const ebpfSyscallRTPprog        RTPexitProgs[] =
{
    {"ProcCreateRawExit", __NR_execve},
    {"ProcCreateRawExit", __NR_execveat},
    {"FileCreateRawExit", __NR_creat},
    {"FileOpenRawExit", __NR_open},
    {"FileOpenRawExit", __NR_openat},
    {"FileOpenRawExit", __NR_RAWACCESS},
    {"FileOpenRawExit", __NR_CREATE},
    {"FileDeleteRawExit", __NR_unlink},
    {"FileDeleteAtRawExit", __NR_unlinkat},
    {"FileDeleteAtCwdRawExit", __NR_unlinkat},
    {"TCPacceptRawExit", __NR_accept},
    {"TCPacceptRawExit", __NR_accept4},
    {"TCPacceptRawExit", __NR_NETWORK},
    {"ProcAccessedRawExit", __NR_ptrace},
    {"UDPrecvRawExit", __NR_recvfrom},
    {"UDPrecvRawExit", __NR_recvmsg},
    {"UDPrecvRawExit", __NR_recvmmsg},
    {"UDPrecvRawExit", __NR_read},
    {"CloseFDRawExit", __NR_close}
};

const ebpfTracepointProg        otherTPprogs4_15[] =
{
    {"sched", "sched_process_exit", "ProcTerminated", __NR_PROCTERM},
    {"tcp", "tcp_set_state", "TCPconnectionOld", __NR_NETWORK},
    {"skb", "consume_skb", "UDPsend", __NR_NETWORK}
};

const ebpfTracepointProg        otherTPprogs4_16[] =
{
    {"sched", "sched_process_exit", "ProcTerminated", __NR_PROCTERM},
    {"sock", "inet_sock_set_state", "TCPconnection", __NR_NETWORK},
    {"skb", "consume_skb", "UDPsend", __NR_NETWORK}
};

const ebpfTelemetryMapObject    mapObjects[] =
{
    {"UDPrecvAge", 0, NULL, NULL},
    {"UDPsendAge", 0, NULL, NULL}
};

// this holds the FDs for the above maps
int mapFds[sizeof(mapObjects) / sizeof(*mapObjects)];

//--------------------------------------------------------------------
//
// syslogHelper
//
// In production, this is a wrapper for syslog().
// In testing, the test harness will provide an implementation such
// that messages destined for syslog() are intercepted instead.
//
//--------------------------------------------------------------------
VOID syslogHelper( int priority, const char* fmt, const char *msg )
{
    if (fmt == NULL || msg == NULL) {
        fprintf(stderr, "syslogHelper invalid params\n");
        return;
    }

    syslog( priority, fmt, msg );
}

//--------------------------------------------------------------------
//
// telemetryReady
//
// Callback from loader library to indicate that it has started up.
//
//--------------------------------------------------------------------
void telemetryReady()
{
    if( OPT_SET( ConfigDefault ) ) {
        SendConfigEvent( "Defaults", NULL );
    } else if( configFile ) {
        ULONG hashType = SysmonCryptoCurrent();		// Default is sha256;
        if(OPT_SET( HashAlgorithms )) {
            unsigned int *hashTypePtr = OPT_VALUE( HashAlgorithms );
            hashType = *hashTypePtr;
        }
        TCHAR buff[256];
        LinuxGetFileHash(hashType, configFile, buff, _countof(buff));
        SendConfigEvent( configFile, buff );
    } else {
        SendConfigEvent( GetCommandLine(), NULL );
    }

    SendStateEvent("Started", STRFILEVER);
    sem_post(startupSem);
}

//--------------------------------------------------------------------
//
// isSimilarTime
//
// Compares a LARGE_INTEGER time (in 100ns increments from epoch)
// against a statx_timestamp (tv_sec and tv_nsec since epoch)
//
//--------------------------------------------------------------------
bool isSimilarTime(CONST PLARGE_INTEGER cur, CONST my_statx_timestamp *test)
{
    if (cur == NULL || test == NULL) {
        fprintf(stderr, "isSimilarTime invalid params\n");
        return false;
    }

    LARGE_INTEGER testLargeTime;

    LinuxFileTimeToLargeInteger(&testLargeTime, test);

    if (llabs(cur->QuadPart - testLargeTime.QuadPart) < (10 * 1000 * 100)) // 100ms
        return true;
    return false;
}

//--------------------------------------------------------------------
//
// processFileOpen
//
// Handles file open events
//
//--------------------------------------------------------------------
void processFileOpen(CONST PSYSMON_EVENT_HEADER eventHdr)
{
    if (eventHdr == NULL) {
        fprintf(stderr, "processFileOpen invalid params\n");
        return;
    }

    char newData[65536];

    PSYSMON_EVENT_HEADER newEventHdr = (PSYSMON_EVENT_HEADER)newData;
    newEventHdr->m_FieldFiltered = 0;
    newEventHdr->m_PreFiltered = 0;
    newEventHdr->m_SequenceNumber = 0;
    newEventHdr->m_SessionId = 0;
    PSYSMON_LINUX_FILE_OPEN event = (PSYSMON_LINUX_FILE_OPEN)&(eventHdr->m_EventBody);

    if (event->m_Flags & O_CREAT &&
            (event->m_Mode & S_IFMT) == S_IFREG // regular file create
    ) {
        // file create event
        newEventHdr->m_EventType = FileCreate;
        PSYSMON_FILE_CREATE newEvent = &newEventHdr->m_EventBody.m_FileCreateEvent;
        newEvent->m_ProcessId = event->m_ProcessId;
        newEvent->m_EventTime.QuadPart = event->m_EventTime.QuadPart;
        newEvent->m_CreateTime.QuadPart = event->m_EventTime.QuadPart;
        newEvent->m_hashType = 0;
        newEvent->m_filehash[0] = 0x00;
        memset(newEvent->m_Extensions, 0, sizeof(newEvent->m_Extensions));
        const char *ptr = (char *)(event + 1);
        char *newPtr = (char *)(newEvent + 1);

        memcpy(newPtr, ptr, event->m_Extensions[LINUX_FO_Sid]);
        newEvent->m_Extensions[FC_Sid] = event->m_Extensions[LINUX_FO_Sid];
        ptr += event->m_Extensions[LINUX_FO_Sid];
        newPtr += event->m_Extensions[LINUX_FO_Sid];

        strcpy(newPtr, ptr);
        newEvent->m_Extensions[FC_ImagePath] = event->m_Extensions[LINUX_FO_ImagePath];
        ptr += event->m_Extensions[LINUX_FO_ImagePath];
        newPtr += event->m_Extensions[LINUX_FO_ImagePath];

        strcpy(newPtr, ptr);
        newEvent->m_Extensions[FC_FileName] = event->m_Extensions[LINUX_FO_PathName];
        newPtr += event->m_Extensions[LINUX_FO_PathName];

        newEventHdr->m_EventSize = (uint32_t)((void *)newPtr - (void *)newEventHdr);

        DispatchEvent(newEventHdr);
    } else if ((event->m_Mode & S_IFMT) == S_IFBLK) { // block device
        newEventHdr->m_EventType = RawAccessRead;
        PSYSMON_RAWACCESS_READ newEvent = &newEventHdr->m_EventBody.m_RawAccessRead;
        newEvent->m_EventSystemTime.QuadPart = event->m_EventTime.QuadPart;
        newEvent->m_ProcessId = event->m_ProcessId;
        memset(newEvent->m_Extensions, 0, sizeof(newEvent->m_Extensions));
        const char *ptr = (char *)(event + 1);
        char *newPtr = (char *)(newEvent + 1);

        memcpy(newPtr, ptr, event->m_Extensions[LINUX_FO_Sid]);
        newEvent->m_Extensions[RR_Sid] = event->m_Extensions[LINUX_FO_Sid];
        ptr += event->m_Extensions[LINUX_FO_Sid];
        newPtr += event->m_Extensions[LINUX_FO_Sid];

        ptr += event->m_Extensions[LINUX_FO_ImagePath];

        strncpy(newEvent->m_Device, ptr, sizeof(newEvent->m_Device));
        newEvent->m_Device[sizeof(newEvent->m_Device)-1] = 0;

        newEventHdr->m_EventSize = (uint32_t)((void *)newPtr - (void *)newEventHdr);

        DispatchEvent(newEventHdr);
    }
}

//--------------------------------------------------------------------
//
// processNetworkEvent
//
// Handles file open events
//
//--------------------------------------------------------------------
void processNetworkEvent(CONST PSYSMON_EVENT_HEADER eventHdr)
{
    if (eventHdr == NULL) {
        fprintf(stderr, "processNetworkEvent invalid params\n");
        return;
    }

    EVENT_TYPE_NETWORK type;
    pid_t pid = 0;
    BYTE sourceAddr[16];
    unsigned short sourcePort;
    BYTE destAddr[16];
    unsigned short destPort;
    bool IPv4 = true;

    PSYSMON_LINUX_NETWORK_EVENT event = (PSYSMON_LINUX_NETWORK_EVENT) &eventHdr->m_EventBody;
    if (event->m_IsTCP) {
        if (event->m_OldState == TCP_SYN_RECV && event->m_NewState == TCP_ESTABLISHED) {
            NetworkTrackerSeenFullAccept(NetworkState, event->m_AddrIsIPv4, event->m_DstAddr, event->m_DstPort,
                    event->m_SrcAddr, event->m_SrcPort, event->m_EventTime.QuadPart);
        } else if (event->m_OldState == TCP_LISTEN && event->m_NewState == TCP_ESTABLISHED) {
            if (NetworkTrackerSeenAccept(NetworkState, event->m_AddrIsIPv4, event->m_SrcAddr, event->m_SrcPort,
                    destAddr, &destPort)) {
                pid = event->m_ProcessId;
            }
        } else if (event->m_OldState == TCP_SYN_RECV && event->m_NewState == TCP_CLOSE) {
            NetworkTrackerCloseAccept(NetworkState, event->m_AddrIsIPv4, event->m_DstAddr, event->m_DstPort,
                    event->m_SrcAddr, event->m_SrcPort);
        } else {
            pid = NetworkTrackerSeenConnect(NetworkState, eventHdr);
            memcpy(destAddr, event->m_DstAddr, 16);
            destPort = event->m_DstPort;
        }

        if (pid != 0) {
            switch (event->m_OldState) {
                case TCP_SYN_SENT:
                    type = EVENT_TYPE_NETWORK_CONNECT;
                    break;
                case TCP_ESTABLISHED:
                    type = EVENT_TYPE_NETWORK_ACCEPT;
                    break;
                default:
                    type = EVENT_TYPE_NETWORK_UNKNOWN;
            }

            CreateNetworkEvent( pid, 0, type, true, event->m_EventTime,
                    0, 0,
                    event->m_AddrIsIPv4, event->m_SrcAddr, event->m_SrcPort,
                    event->m_AddrIsIPv4, destAddr, destPort,
                    NULL, 0, NULL );
        }
    } else {
        int fd = (int)(long)event->m_SockId;
        if (fd == 0) {
            // send
            type = EVENT_TYPE_NETWORK_CONNECT;
            if (NetworkTrackerSeenUdpSend(NetworkState, event->m_AddrIsIPv4, event->m_SrcAddr, event->m_SrcPort,
                    event->m_DstAddr, event->m_DstPort, event->m_ProcessId)) {
                CreateNetworkEvent( event->m_ProcessId, 0, type, false, event->m_EventTime,
                        0, 0,
                        event->m_AddrIsIPv4, event->m_SrcAddr, event->m_SrcPort,
                        event->m_AddrIsIPv4, event->m_DstAddr, event->m_DstPort,
                        NULL, 0, NULL );
            }
        } else {
            // recv
            type = EVENT_TYPE_NETWORK_ACCEPT;
            if (NetworkTrackerSeenUdpRecv(NetworkState, &IPv4, destAddr, &destPort, sourceAddr, &sourcePort,
                    event->m_ProcessId, fd)) {
                CreateNetworkEvent( event->m_ProcessId, 0, type, false, event->m_EventTime,
                        0, 0,
                        IPv4, sourceAddr, sourcePort,
                        IPv4, destAddr, destPort,
                        NULL, 0, NULL );
            }
        }
    }
}

//--------------------------------------------------------------------
//
// getPidFromTid
//
// Gets the process ID for a thread ID
//
//--------------------------------------------------------------------
pid_t getPidFromTid(pid_t tid)
{
    DIR                         *d, *d2;
    struct dirent               *dir, *dir2;
    struct stat                 stStat;
    char                        pidfilepath[PATH_MAX];
    char                        taskfilepath[PATH_MAX];
    pid_t                       pid;

    snprintf(pidfilepath, sizeof(pidfilepath), "/proc/%d", tid);
    //
    // if /proc/TID exists, then the PID == TID
    //
    if (stat(pidfilepath, &stStat) == 0) {
        return tid;
    }

    d = opendir("/proc");
    if (d) {
        while ((dir = readdir(d)) != NULL) {
            if (!StrIsNum(dir->d_name))
                continue;
            pid = atoi(dir->d_name);
            snprintf(taskfilepath, sizeof(taskfilepath), "/proc/%d/task", pid);
            d2 = opendir(taskfilepath);
            if (d2) {
                while ((dir2 = readdir(d2)) != NULL) {
                    if (!StrIsNum(dir2->d_name))
                        continue;
                    if (atoi(dir2->d_name) == tid) {
                        closedir(d2);
                        closedir(d);
                        return pid;
                    }
                }
                closedir(d2);
            }
        }
        closedir(d);
    }
    return -1;
}

//--------------------------------------------------------------------
//
// processProcessAccess
//
// Handles process access events
//
//--------------------------------------------------------------------
void processProcessAccess(CONST PSYSMON_EVENT_HEADER eventHdr)
{
    if (eventHdr == NULL) {
        fprintf(stderr, "processProcessAccess invalid params\n");
        return;
    }

    char newData[65536];
    pid_t pid;
    char exePath[PATH_MAX];
    ssize_t linkSize = 0;
    const char *ptr = NULL;
    char *newPtr = NULL;
    PSYSMON_PROCESS_ACCESS event = &eventHdr->m_EventBody.m_ProcessAccessEvent;
    PSYSMON_EVENT_HEADER newEventHdr = (PSYSMON_EVENT_HEADER)newData;
    PSYSMON_PROCESS_ACCESS newEvent = NULL;
    struct stat st;
    char pathFile[32];

    pid = getPidFromTid(event->m_TargetPid);
    //
    // if we cannot identify the PID from the target TID, just dispatch as is
    //
    if (pid < 0) {
        DispatchEvent(eventHdr);
        return;
    }

    //
    // attempt to fill-in the target TID's image path, from the discovered PID;
    // we cannot edit the existing event so we make a copy to modify.
    // Extensions are variable length and follow the event body, so use the
    // largest buffer possible temporarily.
    //
    memcpy(newData, eventHdr, eventHdr->m_EventSize);
    newEvent = &newEventHdr->m_EventBody.m_ProcessAccessEvent;
    ptr = (char *)(event + 1);
    newPtr = (char *)(newEvent + 1);

    //
    // move pointer beyond existing client image path
    //
    ptr += event->m_Extensions[PA_ClientImage];
    newPtr += newEvent->m_Extensions[PA_ClientImage];

    //
    // retrive path pointed to by process' exe link
    //
    snprintf(exePath, sizeof(exePath), "/proc/%d/exe", pid);
    linkSize = readlink(exePath, newPtr, PATH_MAX);

    //
    // check for success
    //
    if (linkSize >= 0) {
        //
        // null-terminate path and store length in extensions array
        //
        newPtr[linkSize] = 0x00;
        newEvent->m_Extensions[PA_TargetImage] = linkSize + 1;
        newPtr += newEvent->m_Extensions[PA_TargetImage];
    }

    //
    // copy in SidSource
    //
    *(uint64_t *)newPtr = *(uint64_t *)ptr & 0xFFFFFFFF;
    newEvent->m_Extensions[PA_SidSource] = sizeof(uint64_t);
    newPtr += newEvent->m_Extensions[PA_SidSource];

    //
    // retrieve SidTarget
    //
    snprintf(pathFile, 32, "/proc/%d", pid);
    if (stat(pathFile, &st) == 0) {
        *(uint64_t *)newPtr = st.st_uid;
        newEvent->m_Extensions[PA_SidTarget] = sizeof(uint64_t);
        newPtr += sizeof(uint64_t);
    }

    //
    // calculate new event size and dispath
    //
    newEventHdr->m_EventSize = (uint32_t)((void *)newPtr - (void *)newEventHdr);
    DispatchEvent(newEventHdr);
}

//--------------------------------------------------------------------
//
// processProcessCreate
//
// Handles process create events
//
//--------------------------------------------------------------------
void processProcessCreate(CONST PSYSMON_EVENT_HEADER eventHdr)
{
    if(eventHdr == NULL) {
        fprintf(stderr, "processProcessCreate invalid params\n");
        return;
    }

    char newData[65536];

    PSYSMON_EVENT_HEADER newEventHdr = (PSYSMON_EVENT_HEADER)newData;
    newEventHdr->m_FieldFiltered = 0;
    newEventHdr->m_PreFiltered = 0;
    newEventHdr->m_SequenceNumber = 0;
    newEventHdr->m_SessionId = 0;

    PSYSMON_PROCESS_CREATE event = (PSYSMON_PROCESS_CREATE)&(eventHdr->m_EventBody);

    newEventHdr->m_EventType = ProcessCreate;
    PSYSMON_PROCESS_CREATE newEvent = &newEventHdr->m_EventBody.m_ProcessCreateEvent;
    newEvent->m_ProcessId = event->m_ProcessId;
    newEvent->m_ProcessObject = event->m_ProcessObject;
    newEvent->m_ParentProcessObject = event->m_ParentProcessObject;
    newEvent->m_ParentProcessId = event->m_ParentProcessId;
    newEvent->m_AuditUserId = event->m_AuditUserId;
    newEvent->m_SessionId = event->m_SessionId;
    newEvent->m_AuthenticationId.LowPart = event->m_AuthenticationId.LowPart;
    newEvent->m_AuthenticationId.HighPart = event->m_AuthenticationId.HighPart;
    newEvent->m_ProcessKey = event->m_ProcessKey;
    newEvent->m_CreateTime.QuadPart = event->m_CreateTime.QuadPart;

    if(OPT_SET( HashAlgorithms )){
        unsigned int *hashTypePtr = OPT_VALUE( HashAlgorithms );
        newEvent->m_HashType = *hashTypePtr;
    }
    else{
        newEvent->m_HashType = 0;
    }

    memset(newEvent->m_Extensions, 0, sizeof(newEvent->m_Extensions));
    const char *ptr = (char *)(event + 1);
    char *newPtr = (char *)(newEvent + 1);

    memcpy(newPtr, ptr, event->m_Extensions[PC_Sid]);
    newEvent->m_Extensions[PC_Sid] = event->m_Extensions[PC_Sid];
    ptr += event->m_Extensions[PC_Sid];
    newPtr += event->m_Extensions[PC_Sid];

    memcpy(newPtr, ptr, event->m_Extensions[PC_ImagePath]);
    newEvent->m_Extensions[PC_ImagePath] = event->m_Extensions[PC_ImagePath];
    ptr += event->m_Extensions[PC_ImagePath];
    newPtr += event->m_Extensions[PC_ImagePath];

    memcpy(newPtr, ptr, event->m_Extensions[PC_CommandLine]);
    newEvent->m_Extensions[PC_CommandLine] = event->m_Extensions[PC_CommandLine];
    ptr += event->m_Extensions[PC_CommandLine];
    newPtr += event->m_Extensions[PC_CommandLine];

    memcpy(newPtr, ptr, event->m_Extensions[PC_CurrentDirectory]);
    newEvent->m_Extensions[PC_CurrentDirectory] = event->m_Extensions[PC_CurrentDirectory];
    newPtr += event->m_Extensions[PC_CurrentDirectory];

    newEventHdr->m_EventSize = (uint32_t)((void *)newPtr - (void *)newEventHdr);

    DispatchEvent(newEventHdr);
}

//--------------------------------------------------------------------
//
// processFileDelete
//
// Handles file delete events
//
//--------------------------------------------------------------------
void processFileDelete(CONST PSYSMON_EVENT_HEADER eventHdr)
{
    if(eventHdr == NULL) {
        fprintf(stderr, "processFileDelete invalid params\n");
        return;
    }

    char newData[65536];

    PSYSMON_EVENT_HEADER newEventHdr = (PSYSMON_EVENT_HEADER)newData;
    newEventHdr->m_FieldFiltered = 0;
    newEventHdr->m_PreFiltered = 0;
    newEventHdr->m_SequenceNumber = 0;
    newEventHdr->m_SessionId = 0;

    PSYSMON_FILE_DELETE event = (PSYSMON_FILE_DELETE)&(eventHdr->m_EventBody);

    newEventHdr->m_EventType = FileDelete;
    PSYSMON_FILE_DELETE newEvent = &newEventHdr->m_EventBody.m_FileDeleteEvent;
    newEvent->m_ProcessId = event->m_ProcessId;
    newEvent->m_DeleteTime.QuadPart = event->m_DeleteTime.QuadPart;
    newEvent->m_IsExecutable = event->m_IsExecutable;
    newEvent->m_Archived[0] = event->m_Archived[0];
    newEvent->m_TrackerId = event->m_TrackerId;

    newEvent->m_HashType = 0xFF; // 0xFF will not be interpreted as any ALGO_*. Therefore, Hashes field will always be blank.

    memset(newEvent->m_Extensions, 0, sizeof(newEvent->m_Extensions));
    const char *ptr = (char *)(event + 1);
    char *newPtr = (char *)(newEvent + 1);

    memcpy(newPtr, ptr, event->m_Extensions[FD_Sid]);
    newEvent->m_Extensions[FD_Sid] = event->m_Extensions[FD_Sid];
    ptr += event->m_Extensions[FD_Sid];
    newPtr += event->m_Extensions[FD_Sid];

    memcpy(newPtr, ptr, event->m_Extensions[FD_FileName]);
    newEvent->m_Extensions[FD_FileName] = event->m_Extensions[FD_FileName];
    ptr += event->m_Extensions[FD_FileName];
    newPtr += event->m_Extensions[FD_FileName];

    memcpy(newPtr, ptr, event->m_Extensions[FD_ImagePath]);
    newEvent->m_Extensions[FD_ImagePath] = event->m_Extensions[FD_ImagePath];
    ptr += event->m_Extensions[FD_ImagePath];
    newPtr += event->m_Extensions[FD_ImagePath];

    memcpy(newPtr, ptr, event->m_Extensions[FD_Hash]);
    newEvent->m_Extensions[FD_Hash] = event->m_Extensions[FD_Hash];
    newPtr += event->m_Extensions[FD_Hash];

    newEventHdr->m_EventSize = (uint32_t)((void *)newPtr - (void *)newEventHdr);

    DispatchEvent(newEventHdr);
}

//--------------------------------------------------------------------
//
// handleEvent
//
// Receives the eBPF telemetry and sends it to DispatchEvent().
//
//--------------------------------------------------------------------
static void handleEvent(void *ctx, int cpu, void *data, uint32_t size)
{
    if (size < 16 || data == NULL) {
        printf("BAD EVENT: size=%d\n", size);
        badEvents++;
        return;
    }

    PSYSMON_EVENT_HEADER eventHdr = (PSYSMON_EVENT_HEADER)data;
    totalEvents++;

    switch ((DWORD)eventHdr->m_EventType) {
        case LinuxFileOpen:
            processFileOpen(eventHdr);
            break;
        case FileDelete:
            processFileDelete(eventHdr);
            break;
        case LinuxNetworkEvent:
            processNetworkEvent(eventHdr);
            break;
        case ProcessAccess:
            processProcessAccess(eventHdr);
            break;
        case ProcessCreate:
            processProcessCreate(eventHdr);
            break;
        case ProcessTerminate:
        {
            PSYSMON_PROCESS_TERMINATE event = (PSYSMON_PROCESS_TERMINATE)&eventHdr->m_EventBody.m_ProcessTerminateEvent;
            NetworkTrackerUdpProgramTermination(NetworkState, event->m_ProcessId);
            DispatchEvent(eventHdr);
            break;
        }
        default:
            DispatchEvent(eventHdr);
    }
}

//--------------------------------------------------------------------
//
// handleLostEvents
//
// If the userland cannot keep up with the perf ring buffer, then
// this callback will be called to indicate that events were lost.
//
//--------------------------------------------------------------------
void handleLostEvents(void *ctx, int cpu, uint64_t lostCnt)
{
    fprintf(stdout, "Lost %lu events on CPU #%d!\n", lostCnt, cpu);
    numLostNotifications++;
    numLostEvents += lostCnt;
}

//--------------------------------------------------------------------
//
// intHandler
//
// Called on CTRL-C. Tidies up and prints out some stats.
//
//--------------------------------------------------------------------
void intHandler(int code)
{
    printf("\nStopping....\n");
    telemetryCloseAll();

    SendStateEvent("Stopped", STRFILEVER);

    if (eventIdAddr != NULL && eventIdAddr != MAP_FAILED) {
        munmap(eventIdAddr, sizeof(uint64_t));
    }
    if (eventIdFd > 0) {
        close(eventIdFd);
    }

    printf("Total events: %ld, bad events: %ld, ratio = %f\n", totalEvents, badEvents, (double)badEvents / totalEvents);
    printf("Lost events: %ld, in %d notifications\n", numLostEvents, numLostNotifications);

    exit(0);
}

//--------------------------------------------------------------------
//
// PrintBanner
//
// Print program banner.
//
//--------------------------------------------------------------------
void
PrintBanner(
		   const int* argc,
		   const char *argv[]
		   )
{
	printf("\n");
    printf("Sysmon v%s - Monitors system events\n", STRFILEVER);
    printf("%s\n", VER_COMPANY);
    printf("%s\n", VER_COPYRIGHT);
    printf("\n");
}

//--------------------------------------------------------------------
//
// CheckRootPrivs
//
// Check if we are running as root and exit if not.
// In the future we might vary this to check for the privileges
// required to run eBPF instead.
//
//--------------------------------------------------------------------
void
CheckRootPrivs()
{
    if (geteuid() != 0) {
        printf("You need to run Sysmon as root.\n\n");
        exit(ERROR_ELEVATION_REQUIRED);
    }
}

//--------------------------------------------------------------------
//
// WriteRulesBlob
//
// Write the rules to a binary file in the install dir for later
// display.
// Note, size==0 (and therefore data possibly == NULL) is valid,
// resulting in an empty file.
//
//--------------------------------------------------------------------
bool WriteRulesBlob(PVOID data, ULONG size)
{
    int fd;
    size_t written = 0;
    ssize_t writeRet = 0;

    unlink(SYSMON_RULES_FILE);
    fd = creat(SYSMON_RULES_FILE, S_IRUSR | S_IWUSR);
    if (fd < 0)
        return false;

    while (written < size) {
        writeRet = write(fd, data + written, size - written);
        if (writeRet < 0) {
            close(fd);
            unlink(SYSMON_RULES_FILE);
            return false;
        }
        written += writeRet;
    }
    close(fd);
    return true;
}

//--------------------------------------------------------------------
//
// SetSyscallActive
//
// Sets the appropriate syscall for the given event ID
//
//--------------------------------------------------------------------
void SetSyscallActive(bool *s, ULONG eventId)
{
    switch(eventId) {
        case SYSMONEVENT_CREATE_PROCESS_EVENT_value:
            s[__NR_execve] = true;
            s[__NR_execveat] = true;
            break;
        case SYSMONEVENT_NETWORK_CONNECT_EVENT_value:
            s[__NR_accept] = true;
            s[__NR_accept4] = true;
            s[__NR_recvfrom] = true;
            s[__NR_recvmsg] = true;
            s[__NR_recvmmsg] = true;
            s[__NR_read] = true;
            s[__NR_NETWORK] = true;
            break;
        case SYSMONEVENT_PROCESS_TERMINATE_EVENT_value:
            s[__NR_PROCTERM] = true;
            break;
        case SYSMONEVENT_RAWACCESS_READ_EVENT_value:
            s[__NR_open] = true;
            s[__NR_openat] = true;
            s[__NR_RAWACCESS] = true;
            break;
        case SYSMONEVENT_FILE_CREATE_EVENT_value:
            s[__NR_open] = true;
            s[__NR_openat] = true;
            s[__NR_creat] = true;
            s[__NR_CREATE] = true;
            break;
        case SYSMONEVENT_FILE_DELETE_EVENT_value:
            s[__NR_unlink] = true;
            s[__NR_unlinkat] = true;
            break;
        case SYSMONEVENT_ACCESS_PROCESS_EVENT_value:
            s[__NR_ptrace] = true;
            break;
        default:
            break;
    }
}

//--------------------------------------------------------------------
//
// SetActiveSyscalls
//
// Analyse the rules and enable appropriate syscalls
//
//--------------------------------------------------------------------
void SetActiveSyscalls(bool *s)
{
    if (s == NULL) {
        fprintf(stderr, "SetActiveSyscalls invalid params\n");
        return;
    }

    RULE_CONTEXT    ruleContext;
    RULE_REG_EXT    ruleRegExt;
    PRULE_EVENT     ruleEvent = NULL;
    ULONG           index = 0;

    memset( &ruleContext, 0, sizeof( ruleContext ) );
    memset( &ruleRegExt, 0, sizeof( ruleRegExt ) );

    //
    // Set the default rules as active
    //
    for( index = 0; index < AllEventsCount; index++ ) {
        if( AllEvents[index]->RuleName == NULL )
            continue;
        if( AllEvents[index]->Default == Rule_include ) {
            SetSyscallActive( s, AllEvents[index]->EventId );
        }
    }

    //
    // Get the rules
    //
    if( !InitializeRuleContext( &ruleContext ) )
    {
        //
        // No rules
        //
        return;
    }

    if( GetRuleRegExtInformation( &ruleContext, &ruleRegExt ) &&
            ruleRegExt.header.RuleCount > 0 )
    {
        //
        // Set the rules active
        //
        for( ruleEvent = NextRuleEvent( &ruleContext, NULL );
             ruleEvent != NULL;
             ruleEvent = NextRuleEvent( &ruleContext, ruleEvent ) ) {

            SetSyscallActive( s, ruleEvent->EventId );
        }
    }

    ReleaseRuleContext( &ruleContext );
}


//--------------------------------------------------------------------
//
// setConfigFromStoredArgv
//
// Retrieve the command line from the install directory and use it to
// configure Sysmon
//
//--------------------------------------------------------------------
bool setConfigFromStoredArgv(
    PTCHAR          *configFile,
    bool            *activeSyscalls
)
{
    if( configFile == NULL || activeSyscalls == NULL ) {
        fprintf( stderr, "setConfigFromStoredArgv invalid params\n" );
        return false;
    }

    int                         argc = 0;
    static char                 **argv = NULL;
    PVOID                       rules = NULL;
    ULONG                       rulesSize = 0;
    TCHAR                       configHash[256] = { 0 };
    SIZE_T                      z;
    PTCHAR                      parsedConfigFile = NULL;

    //
    // argv persists as its pointers are assigned to the config by
    // ParseCommandLine; so if it is already allocated, free the previous one.
    //
    if( argv != NULL ) {
        free( argv );
    }

    //
    // Read argc and argv from sysmon install directory
    // note: this mallocs argv
    //
    if( !readArgv( &argc, &argv, configFile ) ) {
        fprintf( stderr, "Could not read argv and argc\n" );
        exit( 1 );
    }

    //
    // Unset previous command line arguments
    //
    for( z = 0; z < ConfigOptionTypeCount; z++ ) {
        ConfigOptionType[z].Option->IsSet = false;
        ConfigOptionType[z].Option->Value = NULL;
        ConfigOptionType[z].Option->Size = 0;
    }

    //
    // Parse the command line using the data from manifest.xml.
    // Note that the casing of the rules are the same as specified
    // in the configuration.
    //
    if( !ParseCommandLine( argc, argv, &rules, &rulesSize,
            &parsedConfigFile, configHash, _countof( configHash ) ) ) {
        fprintf( stderr, "Could not parse new rules(keep case)\n" );
        free( argv );
        //
        // argv is static to preserve used memory
        //
        argv = NULL;
        return false;
    }

    //
    // Initialize and load any user-specified max field sizes
    //
    if( !LoadVariableFieldSizes( OPT_VALUE( FieldSizes ) ) ) {
        fprintf( stderr, "Could not load variable field sizes\n" );
        free( argv );
        //
        // argv is static to preserve used memory
        //
        argv = NULL;
        return false;
    }

    //
    // Store any user-specified max field sizes
    //
    if( !writeFieldSizes( OPT_VALUE( FieldSizes ) ) ) {
        fprintf( stderr, "Could not write max field sizes\n" );
        free( argv );
        //
        // argv is static to preserve used memory
        //
        argv = NULL;
        return false;
    }

    //
    // Write rules blob to file. We write the rules in the same case as
    // in the configuration file. This is important to make sure
    // the case is the same when using the -c switch to dump out the configuration
    //
    WriteRulesBlob( rules, rulesSize );


    //
    // Now we want to reinitialize the rules engine with the same set
    // of rules, only this time, make sure we pass Transform=TRUE so
    // that the rules get lower cased which is a requirement for case
    // insensitivity to take place. We can't simply use the old 'rules'
    // since the rules engine holds a reference (set as a result of calling
    // ParseCommandLine above) and will end up freeing it. Instead we make a
    // copy of the rules.
    //
    PVOID rulesCopy = malloc(rulesSize);
    if(rulesCopy == NULL)
    {
        fprintf( stderr, "Failed to allocate memory to rulesCopy\n" );
        free( argv );
        //
        // argv is static to preserve used memory
        //
        argv = NULL;
        return false;
    }

    memcpy(rulesCopy, rules, rulesSize);

    if(!InitializeRules() || !SetRuleBlob(rulesCopy, rulesSize, TRUE))
    {
        fprintf( stderr, "Could not set new rules(lower case)\n" );
        free( argv );
        //
        // argv is static to preserve used memory
        //
        argv = NULL;
        free(rulesCopy);
        return false;
    }

    //
    // Set active rules
    //
    SetActiveSyscalls( activeSyscalls );

    return true;
}

//--------------------------------------------------------------------
//
// configChange
//
// Called when config has changed.
//
//--------------------------------------------------------------------
void configChange()
{
    bool                        activeSyscalls[SYSCALL_ARRAY_SIZE];

    memset( activeSyscalls, 0, sizeof( activeSyscalls ) );

    //
    // Load the command line from the stored argv
    //
    if ( !setConfigFromStoredArgv( &configFile, activeSyscalls ) )
        return;

    //
    // Update the EBPF programs
    //
    telemetryUpdateSyscalls( activeSyscalls );

    //
    // Send config change event
    //
    ULONG hashType = SysmonCryptoCurrent();		// Default is sha256;
    if(OPT_SET( HashAlgorithms )) {
        unsigned int *hashTypePtr = OPT_VALUE( HashAlgorithms );
        hashType = *hashTypePtr;
    }
    TCHAR buff[256];
    LinuxGetFileHash(hashType, configFile, buff, _countof(buff));
    SendConfigEvent( configFile, buff );

    fflush(NULL);
}


//--------------------------------------------------------------------
//
// HasCustomConfiguration
//
// Return TRUE if any custom configuration was set (change in settings).
//
//--------------------------------------------------------------------
BOOLEAN
HasCustomConfiguration(
    VOID
    )
{
    SIZE_T  index;

    for( index = 0; index < ConfigOptionTypeCount; index++ ) {

        if( !ConfigOptionType[index].CommandLineOnly &&
            ConfigOptionType[index].Option->IsSet ) {
            return TRUE;
        }
    }

    return FALSE;
}

//--------------------------------------------------------------------
//
// main
//
// Entrypoint to the application for installation, configuration and
// running the service instance.
//
//--------------------------------------------------------------------
int
main(
    int argc,
    char *argv[]
)
{
    PVOID                       rules = NULL;
	ULONG                       rulesSize = 0;
    PTCHAR                      debugModeOption;
	TCHAR                       configHash[256] = { 0 };
	CONSOLE_SCREEN_BUFFER_INFO	csbi;
	struct 	                    winsize winSize;
    pid_t                       pid;
    bool                        forceUninstall = false;
    bool                        activeSyscalls[SYSCALL_ARRAY_SIZE];
    bool                        nothingToChange = false;
    int                         *retPtr = NULL;

    //
    // Find boot time and clock tick interval, used for calculating process start times
    //
    SetBootTime();

	LIBXML_TEST_VERSION

    umask(SYSMON_UMASK);

	if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &winSize) == 0) {
		csbi.dwSize.X = winSize.ws_col;
	} else {
		csbi.dwSize.X = 80;
	}

	PrintBanner( &argc, (const char **)argv );

	//
	// Is it just looking for help
	//
	if( argc >= 2 &&
		argv[1][0] == '-' &&
		( argv[1][1] == '?' ||
		  !strcasecmp( argv[1] + 1, "h" ) ||
		  !strcasecmp( argv[1] + 1, "help" ) ) ) {

		if( argc > 2 ) {

			if( !strcasecmp( argv[2], "config" ) || !strcasecmp( argv[2], "configuration" ) ) {

				ConfigUsage( &csbi );
				return ERROR_SUCCESS;
			}
		}

		//
		// Expected behaviour so return success
		//
		Usage( argv[0], &csbi );
		return ERROR_SUCCESS;
	}

	//
	// Parse the command line using the data from manifest.xml
	//
	if( !ParseCommandLine( argc, argv, &rules, &rulesSize,
					&configFile, configHash, _countof( configHash) ) ) {

		return Usage( argv[0], &csbi );
	}

    //
    // Initialize and load any user-specified max field sizes
    //
    if( !LoadVariableFieldSizes( OPT_VALUE( FieldSizes ) ) ) {
        fprintf( stderr, "Could not load variable field sizes\n" );
        return Usage( argv[0], &csbi );
    }

    //
    // Print schema
    //
    if( OPT_SET( PrintSchema ) ) {

        PrintSchema();
        return ERROR_SUCCESS;
    }

    if( !OPT_SET(Configuration) && OPT_SET(ConfigDefault) ) {

        printf( "The '--' switch must be used with -c switch (config update) to set defaults.\n\n" );
        return ERROR_INVALID_PARAMETER;
    }

    if( OPT_SET(ClipboardInstance) ||
        OPT_SET(DriverName) ||
        OPT_SET(ArchiveDirectory) ||
        OPT_SET(CaptureClipboard) ||
        OPT_SET(CheckRevocation)
        ) {
        printf("\nOption not implemented on Linux.\n\n");
        return ERROR_INVALID_PARAMETER;
    }

    if( OPT_SET( DebugMode ) ) {

        g_DebugMode = TRUE;
        debugModeOption = OPT_VALUE( DebugMode );
        if( debugModeOption ) {

            if( _tcsicmp( debugModeOption, _T("verbose") ) ) {
                _tprintf( _T( "Possible options for DebugMode: verbose\n\n" ) );
                return ERROR_INVALID_PARAMETER;
            }
            g_DebugModeVerbose = TRUE;
        }
    }

    CheckRootPrivs();

    if ( OPT_SET(UnInstall) ) {
        const char *uninstallModeOption = OPT_VALUE( UnInstall );
        if ( uninstallModeOption) {
            if( _tcsicmp( uninstallModeOption, _T("force") ) != 0 ) {

                _tprintf( _T("Invalid option for -u.\n\n") );
                return Usage( argv[0], &csbi );
            }
            forceUninstall = true;
        }

        stopSysmonService();
        uninstall();
        killOtherSysmon(forceUninstall);
        printf("Sysmon stopped.\n");
        return ERROR_SUCCESS;
    }

    if ( OPT_SET(Configuration) ) {
        if( OPT_VALUE(Configuration) == NULL ) {

            nothingToChange = !HasCustomConfiguration();
        } else {

            nothingToChange = FALSE;
        }

        //
        // If we received -c -- check that there is no other options set
        // if we received -c and others check that something will change?
        //
        if( OPT_SET(ConfigDefault) ) {

            if( !nothingToChange ) {

                _tprintf( _T("Cannot use specific settings with enforcing defaults.\n\n") );
                return ERROR_INVALID_PARAMETER;
            }

            _tprintf( _T("Updating configuration to use all defaults.\n") );

        } else if( nothingToChange && rules == NULL && rulesSize == 0 ) {

            //
            // Display current configuration
            //
            if (sysmonIsRunning()) {
                if (fileExists(SYSMON_RULES_FILE)) {
                    DumpConfiguration();
                } else {
                    printf("No config to display\n");
                }
                return ERROR_SUCCESS;
            } else {
                printf("Sysmon is not running\n");
                return ERROR_INVALID_PARAMETER;
            }
        }

        if( !sysmonIsRunning() ) {

            _tprintf( _T("Error: Sysmon is not installed.\n") );
        }

        //
        // Update configuration
        //
        if( OPT_SET( ConfigDefault ) || configFile == NULL ) {

            //
            // create empty config file
            //
            unlink(SYSMON_CONFIG_FILE);
            if (!createEmptyConfigFile()) {
                fprintf(stderr, "Cannot create empty config file\n");
                return ERROR_INVALID_PARAMETER;
            }
        }
        else {
            if (!copyConfigFile(configFile)) {
                fprintf(stderr, "Cannot copy the config file\n");
                return ERROR_INVALID_PARAMETER;
            }
        }

        if (!writeArgv(argc, argv)) {
            fprintf(stderr, "Cannot write argv and argc\n");
            return ERROR_INVALID_PARAMETER;
        }

        signalConfigChange();
        return ERROR_SUCCESS;

    }

    if ( OPT_SET(Install) ) {

        killOtherSysmon(true); // just to be sure

        if (!installFiles(true)) {
            fprintf(stderr, "Cannot install Sysmon files\n");
            exit(1);
        }

        if ( !OPT_SET(Service) ) {
            stopSysmonService();

            if (configFile != NULL) {
                if (!copyConfigFile(configFile)) {
                    fprintf(stderr, "Cannot copy the config file\n");
                    exit(1);
                }
            } else {
                //
                // create empty config file
                //
                unlink(SYSMON_CONFIG_FILE);
                if (!createEmptyConfigFile()) {
                    fprintf(stderr, "Cannot create empty config file\n");
                    exit(1);
                }
            }

            //
            // store the command line for when we restart as a service
            //
            if (!writeArgv(argc, argv)) {
                fprintf(stderr, "Cannot write argv and argc\n");
                exit(1);
            }
        }

        //
        // If Sysmon is not currently running as a service (e.g. started by
        // systemd or init.d) then start it as a service by replacing this
        // execution with the shell invoker that starts the service.  If
        // Sysmon is already running as a service, or it cannot start as a
        // service (missing systemd and missing init.d) then continue.
        //
        startSysmonService();

        //
        // Retrieve the command line used to install Sysmon - note the systemd
        // service will have started Sysmon with a generic command line and we
        // want to start it up with the original command line.
        //
        memset( activeSyscalls, 0, sizeof( activeSyscalls ) );
        setConfigFromStoredArgv( &configFile, activeSyscalls );

        if ( OPT_SET(BTF) ) {
            btfPath = OPT_VALUE( BTF );
        }

        bool debug = false;
        if( OPT_SET( DebugMode ) ) {
            debug = true;
        }

        struct stat st;
        bool btfEnabled = stat(BTF_KERNEL_FILE, &st) < 0 ? false : true;

        const ebpfTelemetryObject   kernelObjs[] =
        {
            {
                KERN_4_15_OBJ, {4, 15}, {4, 16}, false,
                sizeof(TPenterProgs) / sizeof(*TPenterProgs),
                TPenterProgs,
                sizeof(TPexitProgs) / sizeof(*TPexitProgs),
                TPexitProgs,
                0, NULL, 0, NULL, // No raw tracepoint programs
                activeSyscalls,
                sizeof(otherTPprogs4_15) / sizeof(*otherTPprogs4_15),
                otherTPprogs4_15
            },
            {
                KERN_4_16_OBJ, {4, 16}, {4, 17}, false,
                sizeof(TPenterProgs) / sizeof(*TPenterProgs),
                TPenterProgs,
                sizeof(TPexitProgs) / sizeof(*TPexitProgs),
                TPexitProgs,
                0, NULL, 0, NULL, // No raw tracepoint programs
                activeSyscalls,
                sizeof(otherTPprogs4_16) / sizeof(*otherTPprogs4_15),
                otherTPprogs4_16
            },
            {
                KERN_4_17_5_1_OBJ, {4, 17}, {5, 2}, true,
                0, NULL, 0, NULL, // No traditional tracepoint programs
                sizeof(RTPenterProgs) / sizeof(*RTPenterProgs),
                RTPenterProgs,
                sizeof(RTPexitProgs) / sizeof(*RTPexitProgs),
                RTPexitProgs,
                activeSyscalls,
                sizeof(otherTPprogs4_16) / sizeof(*otherTPprogs4_16),
                otherTPprogs4_16
            },
            {
                KERN_5_2_OBJ, {5, 2}, {5, 3}, true,
                0, NULL, 0, NULL, // No traditional tracepoint programs
                sizeof(RTPenterProgs) / sizeof(*RTPenterProgs),
                RTPenterProgs,
                sizeof(RTPexitProgs) / sizeof(*RTPexitProgs),
                RTPexitProgs,
                activeSyscalls,
                sizeof(otherTPprogs4_16) / sizeof(*otherTPprogs4_16),
                otherTPprogs4_16
            },
            {
                KERN_5_3_5_5_OBJ, {5, 3}, {5, 6}, true,
                0, NULL, 0, NULL, // No traditional tracepoint programs
                sizeof(RTPenterProgs) / sizeof(*RTPenterProgs),
                RTPenterProgs,
                sizeof(RTPexitProgs) / sizeof(*RTPexitProgs),
                RTPexitProgs,
                activeSyscalls,
                sizeof(otherTPprogs4_16) / sizeof(*otherTPprogs4_16),
                otherTPprogs4_16
            },
            {
                KERN_5_6__OBJ, {5, 6}, {0, 0}, true,
                0, NULL, 0, NULL, // No traditional tracepoint programs
                sizeof(RTPenterProgs) / sizeof(*RTPenterProgs),
                RTPenterProgs,
                sizeof(RTPexitProgs) / sizeof(*RTPexitProgs),
                RTPexitProgs,
                activeSyscalls,
                sizeof(otherTPprogs4_16) / sizeof(*otherTPprogs4_16),
                otherTPprogs4_16
            }
        };

        ebpfTelemetryObject   kernelObjs_core[] =
        {
            {
                KERN_4_15_CORE_OBJ, {4, 15}, {4, 16}, false,
                sizeof(TPenterProgs) / sizeof(*TPenterProgs),
                TPenterProgs,
                sizeof(TPexitProgs) / sizeof(*TPexitProgs),
                TPexitProgs,
                0, NULL, 0, NULL, // No raw tracepoint programs
                activeSyscalls,
                sizeof(otherTPprogs4_15) / sizeof(*otherTPprogs4_15),
                otherTPprogs4_15
            },
            {
                KERN_4_16_CORE_OBJ, {4, 16}, {4, 17}, false,
                sizeof(TPenterProgs) / sizeof(*TPenterProgs),
                TPenterProgs,
                sizeof(TPexitProgs) / sizeof(*TPexitProgs),
                TPexitProgs,
                0, NULL, 0, NULL, // No raw tracepoint programs
                activeSyscalls,
                sizeof(otherTPprogs4_16) / sizeof(*otherTPprogs4_15),
                otherTPprogs4_16
            },
            {
                KERN_4_17_5_1_CORE_OBJ, {4, 17}, {5, 2}, true,
                0, NULL, 0, NULL, // No traditional tracepoint programs
                sizeof(RTPenterProgs) / sizeof(*RTPenterProgs),
                RTPenterProgs,
                sizeof(RTPexitProgs) / sizeof(*RTPexitProgs),
                RTPexitProgs,
                activeSyscalls,
                sizeof(otherTPprogs4_16) / sizeof(*otherTPprogs4_16),
                otherTPprogs4_16
            },
            {
                KERN_5_2_CORE_OBJ, {5, 2}, {5, 3}, true,
                0, NULL, 0, NULL, // No traditional tracepoint programs
                sizeof(RTPenterProgs) / sizeof(*RTPenterProgs),
                RTPenterProgs,
                sizeof(RTPexitProgs) / sizeof(*RTPexitProgs),
                RTPexitProgs,
                activeSyscalls,
                sizeof(otherTPprogs4_16) / sizeof(*otherTPprogs4_16),
                otherTPprogs4_16
            },
            {
                KERN_5_3_5_5_CORE_OBJ, {5, 3}, {5, 6}, true,
                0, NULL, 0, NULL, // No traditional tracepoint programs
                sizeof(RTPenterProgs) / sizeof(*RTPenterProgs),
                RTPenterProgs,
                sizeof(RTPexitProgs) / sizeof(*RTPexitProgs),
                RTPexitProgs,
                activeSyscalls,
                sizeof(otherTPprogs4_16) / sizeof(*otherTPprogs4_16),
                otherTPprogs4_16
            },
            {
                KERN_5_6__CORE_OBJ, {5, 6}, {0, 0}, true,
                0, NULL, 0, NULL, // No traditional tracepoint programs
                sizeof(RTPenterProgs) / sizeof(*RTPenterProgs),
                RTPenterProgs,
                sizeof(RTPexitProgs) / sizeof(*RTPexitProgs),
                RTPexitProgs,
                activeSyscalls,
                sizeof(otherTPprogs4_16) / sizeof(*otherTPprogs4_16),
                otherTPprogs4_16
            }
        };


        const ebpfTelemetryConfig sysmonConfig = (ebpfTelemetryConfig)
        {
            g_bootSecSinceEpoch,
            true, // enable raw socket capture
            btfEnabled ? sizeof(kernelObjs_core) / sizeof(*kernelObjs_core) : sizeof(kernelObjs) / sizeof(*kernelObjs),
            btfEnabled ? kernelObjs_core : kernelObjs,
            sizeof(defPaths) / sizeof(*defPaths),
            defPaths,
            sizeof(mapObjects) / sizeof(*mapObjects),
            mapObjects,
            btfPath,
            debug
        };

        //
        // Set up network tracker
        //
        NetworkState = NetworkTrackerInit(15 * 60, 1 * 60); // connections are stale after 15 mins
                                                            // check after 1 min

        //
        // Set up syslog
        //
        openlog( "sysmon", LOG_NOWAIT, LOG_USER );
        signal( SIGINT, intHandler );
        signal( SIGTERM, intHandler );

        struct stat event_stat;
        bool init_eventId = false;
        if (stat(EVENTID_FILE, &event_stat) != 0) {
            init_eventId = true;
        }

        eventIdFd = open(EVENTID_FILE, O_RDWR | O_CREAT, S_IRUSR | S_IWUSR);
        if (eventIdFd > 0) {
            if (init_eventId) {
                posix_fallocate(eventIdFd, 0, sizeof(uint64_t));
            }
            eventIdAddr = (uint64_t *)mmap(NULL, sizeof(uint64_t), PROT_READ | PROT_WRITE, MAP_SHARED, eventIdFd, 0);
            if ((eventIdAddr != NULL && eventIdAddr != MAP_FAILED) && init_eventId) {
                *eventIdAddr = 0;
            }
        }

        fflush(NULL);

        sem_unlink(STARTUP_SEM_NAME);
        startupSem = sem_open(STARTUP_SEM_NAME, O_CREAT | O_EXCL, S_IRUSR | S_IWUSR, 0);
        if (startupSem == SEM_FAILED) {
            fprintf(stderr, "Cannot create semaphore\n");
            exit(1);
        }

        //
        // create shared memory to pass back the return code
        //
        retPtr = (int *)mmap(NULL, sizeof(int), PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
        if (retPtr == NULL) {
            fprintf(stderr, "Failed to mmap shared memory\n");
            return E_EBPF_CATASTROPHIC;
        }

        //
        // fork in order to make the execution a service
        // and also to allow the process to become a session leader, which is
        // essential for automatic offsets discovery
        //
        pid = fork();
        if (pid < 0) {
            fprintf(stderr, "Cannot fork\n");
            exit(1);
        } else if (pid > 0) {
            //
            // wait for everything to start
            //
            sem_wait(startupSem);
            sem_close(startupSem);
            sem_unlink(STARTUP_SEM_NAME);
            if (*retPtr != E_EBPF_SUCCESS) {
                fprintf(stderr, "Telemetry failed to start: %s\n", eBPFstrerror(*retPtr));
            }
            exit(*retPtr);
        }

        *retPtr = telemetryStart( &sysmonConfig, handleEvent, handleLostEvents, telemetryReady, configChange,
                NULL, (const char **)argv, mapFds );
        sem_post(startupSem);

        closelog();

        return *retPtr;
    }

    Usage( argv[0], &csbi );
    return ERROR_INVALID_PARAMETER;
}

