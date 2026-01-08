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
// linuxTypes.h
//
// Defines and typedefs to map to Windows types.
//
//====================================================================

#pragma once

#include <stdbool.h>
#include <stdint.h>
#include <assert.h>
#include <linux/limits.h>
#include <ctype.h>

typedef long unsigned int size_t;

//
// Basics
//
#if !defined TRUE
#define TRUE true
#endif
#if !defined FALSE
#define FALSE false
#endif

#define CONST const

#define VOID void
typedef VOID *PVOID, *LPVOID;

typedef bool BOOL, *PBOOL;
typedef bool BOOLEAN;

typedef char CHAR, *PCHAR, *LPCH, *PCH, INT8;
typedef CONST CHAR *LPCCH, *PCCH;
typedef CHAR *NPSTR, *LPSTR, *PSTR;
typedef PSTR *PZPSTR;
typedef CONST PSTR *PCZPSTR;
typedef CONST CHAR *LPCSTR, *PCSTR;
typedef PCSTR *PZPCSTR;
typedef CHAR *PZZSTR;
typedef CONST CHAR *PCZZSTR;
typedef CHAR *PNZCH;
typedef CONST CHAR *PCNZCH;

typedef unsigned char UCHAR, *PUCHAR, UINT8;
typedef uint8_t BYTE, *PBYTE;

typedef short SHORT, *PSHORT, INT16;
typedef unsigned short USHORT, *PUSHORT, UINT16;
typedef unsigned short WORD;

typedef int INT;
typedef unsigned int UINT;

typedef uint32_t DWORD, *PDWORD, *UINT_PTR;
typedef int32_t LONG, *PLONG, INT32;
typedef uint32_t ULONG, *PULONG, *ULONG_PTR, UINT32;

typedef int64_t INT64, LONGLONG;
typedef uint64_t ULONG64, UINT64, ULONGLONG, *PULONGLONG, DWORD64;

typedef int errno_t;
typedef uint32_t NTSTATUS;
typedef size_t SIZE_T, *PSIZE_T;
typedef uint64_t SID, *PSID;

typedef uint64_t SERVICE_STATUS;
typedef uint64_t SERVICE_STATUS_HANDLE;
typedef uint32_t HRESULT;
typedef PVOID SRWLOCK, *PSRWLOCK;
typedef PVOID HANDLE, *PHANDLE, HMODULE, REGHANDLE;
typedef HANDLE HKEY;


//
// Windows compiler annotaions
//
#define ANYSIZE_ARRAY 1
#define __stdcall
#define WINAPI

#define _In_
#define _Inout_
#define _Out_
#define _Outptr_
#define _In_opt_
#define _Inout_opt_
#define _Out_opt_
#define _Outptr_opt_
#define _In_reads_(s)
#define _In_reads_opt_(s)

#define MAX_PATH PATH_MAX

typedef HANDLE EVT_HANDLE;
typedef HANDLE* PEVT_HANDLE;
typedef HANDLE EVT_OBJECT_ARRAY_PROPERTY_HANDLE;

//
// UNICODE (Wide Character) types
//
typedef unsigned short WCHAR;    // wc,   16-bit UNICODE character

typedef WCHAR *PWCHAR, *LPWCH, *PWCH;
typedef CONST WCHAR *LPCWCH, *PCWCH;

typedef WCHAR *NWPSTR, *LPWSTR, *PWSTR;
typedef PWSTR *PZPWSTR;
typedef CONST PWSTR *PCZPWSTR;
typedef WCHAR *LPUWSTR, *PUWSTR;
typedef CONST WCHAR *LPCWSTR, *PCWSTR;
typedef PCWSTR *PZPCWSTR;
typedef CONST WCHAR *LPCUWSTR, *PCUWSTR;

typedef WCHAR *PZZWSTR;
typedef CONST WCHAR *PCZZWSTR;
typedef WCHAR *PUZZWSTR;
typedef CONST WCHAR *PCUZZWSTR;

typedef WCHAR *PNZWCH;
typedef CONST WCHAR *PCNZWCH;
typedef WCHAR *PUNZWCH;
typedef CONST WCHAR *PCUNZWCH;

typedef CONST WCHAR *LPCWCHAR, *PCWCHAR;
typedef CONST WCHAR *LPCUWCHAR, *PCUWCHAR;

typedef WCHAR *LPOLESTR;

//
//  UCS (Universal Character Set) types
//
typedef unsigned long UCSCHAR;

#define UCSCHAR_INVALID_CHARACTER (0xffffffff)
#define MIN_UCSCHAR (0)
#define MAX_UCSCHAR (0x0010FFFF)

typedef UCSCHAR *PUCSCHAR;
typedef const UCSCHAR *PCUCSCHAR;

typedef UCSCHAR *PUCSSTR;
typedef UCSCHAR *PUUCSSTR;

typedef const UCSCHAR *PCUCSSTR;
typedef const UCSCHAR *PCUUCSSTR;

typedef UCSCHAR *PUUCSCHAR;
typedef const UCSCHAR *PCUUCSCHAR;

//
// Neutral ANSI/UNICODE types and macros
// Map tchar to char
//
typedef char TCHAR, *PTCHAR;
typedef unsigned char TBYTE, *PTBYTE;

typedef LPCH LPTCH, PTCH;
typedef LPCCH LPCTCH, PCTCH;
typedef LPSTR PTSTR, LPTSTR, PUTSTR, LPUTSTR;
typedef LPCSTR PCTSTR, LPCTSTR, PCUTSTR, LPCUTSTR;
typedef PZZSTR PZZTSTR, PUZZTSTR;
typedef PCZZSTR PCZZTSTR, PCUZZTSTR;
typedef PNZCH PNZTCH, PUNZTCH;
typedef PCNZCH PCNZTCH, PCUNZTCH;

#define __TEXT(quote) quote
#define TEXT(quote) __TEXT(quote)
#define _T(x) x

//
// Coord for console screen struct
//
typedef struct {
    SHORT X;
    SHORT Y;
} COORD, *PCOORD;

typedef struct {
    COORD dwSize;
} CONSOLE_SCREEN_BUFFER_INFO, *PCONSOLE_SCREEN_BUFFER_INFO;

//
// Error codes
//
#define S_OK 0
#define E_ABORT         0x80004004
#define E_ACCESSDENIED  0x80070005
#define E_FAIL          0x80004005
#define E_HANDLE        0x80070006
#define E_INVALIDARG    0x80070057
#define E_NOINTERFACE   0x80004002
#define E_NOTIMPL       0x80004001
#define E_OUTOFMEMORY   0x8007000E
#define E_POINTER       0x80004003
#define E_UNEXPECTED    0x8000FFFF

#define ERROR_SUCCESS 0L
#define ERROR_FILE_NOT_FOUND 2L
#define ERROR_INVALID_BLOCK 9L
#define ERROR_INVALID_DATA 13L
#define ERROR_OUTOFMEMORY 14L
#define ERROR_INVALID_PARAMETER 87L
#define ERROR_BUFFER_OVERFLOW 111L
#define ERROR_INSUFFICIENT_BUFFER 122L
#define ERROR_NO_MATCH 1169L
#define ERROR_ELEVATION_REQUIRED 740L

#if defined DEBUG || defined _DEBUG
#define D_ASSERT(x) assert(x)
#else
#define D_ASSERT(x)
#endif
#define _ASSERT(x) assert(x)
#define FAILED(hr) (((HRESULT)(hr)) < 0)
#define SUCCEEDED(hr) (((HRESULT)(hr)) >= 0)

//
// Array macros
//
#define _countof(_x) (sizeof(_x)/sizeof(*_x))
#define ARRAYSIZE(_x) (sizeof(_x)/sizeof(*_x))

//
// Map tchar to char
//
#define _tstoi(a) atoi(a)
#define _istalnum(a) isalnum(a)
#define _tcscpy(a,b) strcpy(a,b)
#define _tcsncpy(a,b,c) strncpy(a,b,c)
#define _tcsncpy_s(a,b,c,_TRUNCATE) snprintf(a,b,"%s",c)
#define _tcsdup(x) strdup(x)
#define _tcslen(x) strlen(x)
#define _tcsicmp(a,b) strcasecmp(a,b)
#define _tcscmp(a,b) strcmp(a,b)
#define _tcsnicmp(a,b,c) strncasecmp(a,b,c)
#define _tcsncmp(a,b,c) strncmp(a,b,c)
#define _tcschr(a,b) strchr(a,b)
#define _tcsrchr(a,b) strrchr(a,b)
#define _tcstoul(a,b,c) strtoul(a,b,c)
#define _tcsstr(a,b) strstr(a,b)
#define _tcsncat_s(a,b,c,_TRUNCATE) strncat(a,b,c)
#define _tcstok_s(a,b,c) strtok_r(a,b,c)

#define _fputts(a,b) fputs(a,b)
#define _fputtc(a,b) fputc(a,b)
#define _fgetts(a,b,c) fgets(a,b,c)

#define _ftprintf(...) fprintf(__VA_ARGS__)
#define _ftprintf_s(...) fprintf(__VA_ARGS__)
#define _tprintf(...) printf(__VA_ARGS__)
#define _tprintf_s(...) printf(__VA_ARGS__)
#define _stprintf(...) sprintf(__VA_ARGS__)
#define _stprintf_s(...) snprintf(__VA_ARGS__)
#define _sntprintf(...) snprintf(__VA_ARGS__)
#define _sntprintf_s(a,b,c,...) snprintf(a,b,__VA_ARGS__)

#define _tfopen(a,b) fopen(a,b)

#define _tstat(a,b) stat(a,b)

#define ZeroMemory(Destination,Length) memset((Destination),0,(Length))

#define Sleep(a) usleep(a * 1000)

#define __fallthrough __attribute__((fallthrough))

#define FIELD_OFFSET(a,b) offsetof(a,b)

#define CONTAINING_RECORD(address, type, field) ((type *)( \
                                                  (PCHAR)(address) - \
                                                  (PCHAR)(ULONG_PTR)(&((type *)0)->field)))

#define NT_SUCCESS(x) (((uint32_t)x) < 0x40000000 ? TRUE : FALSE)

typedef enum _EVT_LOGIN_CLASS {
    EvtRpcLogin
} EVT_LOGIN_CLASS;

typedef enum _EVT_PUBLISHER_METADATA_PROPERTY_ID {
    EvtPublisherMetadataPublisherGuid,
    EvtPublisherMetadataResourceFilePath,
    EvtPublisherMetadataParameterFilePath,
    EvtPublisherMetadataMessageFilePath,
    EvtPublisherMetadataHelpLink,
    EvtPublisherMetadataPublisherMessageID,
    EvtPublisherMetadataChannelReferences,
    EvtPublisherMetadataChannelReferencePath,
    EvtPublisherMetadataChannelReferenceIndex,
    EvtPublisherMetadataChannelReferenceID,
    EvtPublisherMetadataChannelReferenceFlags,
    EvtPublisherMetadataChannelReferenceMessageID,
    EvtPublisherMetadataLevels,
    EvtPublisherMetadataLevelName,
    EvtPublisherMetadataLevelValue,
    EvtPublisherMetadataLevelMessageID,
    EvtPublisherMetadataTasks,
    EvtPublisherMetadataTaskName,
    EvtPublisherMetadataTaskEventGuid,
    EvtPublisherMetadataTaskValue,
    EvtPublisherMetadataTaskMessageID,
    EvtPublisherMetadataOpcodes,
    EvtPublisherMetadataOpcodeName,
    EvtPublisherMetadataOpcodeValue,
    EvtPublisherMetadataOpcodeMessageID,
    EvtPublisherMetadataKeywords,
    EvtPublisherMetadataKeywordName,
    EvtPublisherMetadataKeywordValue,
    EvtPublisherMetadataKeywordMessageID,
    EvtPublisherMetadataPropertyIdEND
} EVT_PUBLISHER_METADATA_PROPERTY_ID;

typedef struct _LIST_ENTRY {
    struct _LIST_ENTRY *Flink;
    struct _LIST_ENTRY *Blink;
} LIST_ENTRY, *PLIST_ENTRY, PRLIST_ENTRY;

typedef union _LARGE_INTEGER {
    struct {
        DWORD LowPart;
        LONG  HighPart;
    };
    LONGLONG QuadPart;
} LARGE_INTEGER, *PLARGE_INTEGER;

typedef struct {
    DWORD LowPart;
    LONG  HighPart;
} LUID, *PLUID;

typedef struct _SYSTEMTIME {
    WORD wYear;
    WORD wMonth;
    WORD wDayOfWeek;
    WORD wDay;
    WORD wHour;
    WORD wMinute;
    WORD wSecond;
    WORD wMilliseconds;
} SYSTEMTIME, *PSYSTEMTIME, *LPSYSTEMTIME;

typedef struct {
    ULONG   Data1;
    USHORT  Data2;
    USHORT  Data3;
    UCHAR   Data4[8];
} GUID, *PGUID, IID, *PIID, *REFGUID;
typedef CONST GUID *LPCGUID;

typedef struct _FILETIME {
  DWORD dwLowDateTime;
  DWORD dwHighDateTime;
} FILETIME, *PFILETIME, *LPFILETIME;

typedef struct _EVT_VARIANT {
    union {
        BOOL       BooleanVal;
        INT8       SByteVal;
        INT16      Int16Val;
        INT32      Int32Val;
        INT64      Int64Val;
        UINT8      ByteVal;
        UINT16     UInt16Val;
        UINT32     UInt32Val;
        UINT64     UInt64Val;
        float      SingleVal;
        double     DoubleVal;
        ULONGLONG  FileTimeVal;
        SYSTEMTIME *SysTimeVal;
        GUID       *GuidVal;
        LPCWSTR    StringVal;
        LPCSTR     AnsiStringVal;
        PBYTE      BinaryVal;
        PSID       SidVal;
        size_t     SizeTVal;
        BOOL       *BooleanArr;
        INT8       *SByteArr;
        INT16      *Int16Arr;
        INT32      *Int32Arr;
        INT64      *Int64Arr;
        UINT8      *ByteArr;
        UINT16     *UInt16Arr;
        UINT32     *UInt32Arr;
        UINT64     *UInt64Arr;
        float      *SingleArr;
        double     *DoubleArr;
        FILETIME   *FileTimeArr;
        SYSTEMTIME *SysTimeArr;
        GUID       *GuidArr;
        LPWSTR     *StringArr;
        LPSTR      *AnsiStringArr;
        PSID       *SidArr;
        size_t     *SizeTArr;
        EVT_HANDLE EvtHandleVal;
        LPCWSTR    XmlVal;
        LPCWSTR    *XmlValArr;
    };
    DWORD Count;
    DWORD Type;
} EVT_VARIANT, *PEVT_VARIANT;

typedef struct {
    USHORT      Id;
    UCHAR       Version;
    UCHAR       Channel;
    UCHAR       Level;
    UCHAR       Opcode;
    USHORT      Task;
    ULONGLONG   Keyword;
} EVENT_DESCRIPTOR, *PEVENT_DESCRIPTOR;
typedef CONST EVENT_DESCRIPTOR *PCEVENT_DESCRIPTOR;

typedef struct _EVENT_DATA_DESCRIPTOR {
    ULONGLONG Ptr;
    ULONG     Size;
    union {
        ULONG Reserved;
        struct {
            UCHAR  Type;
            UCHAR  Reserved1;
            USHORT Reserved2;
        };
    };
} EVENT_DATA_DESCRIPTOR, *PEVENT_DATA_DESCRIPTOR;

typedef struct _EVENT_FILTER_DESCRIPTOR {
    ULONGLONG Ptr;
    ULONG     Size;
    ULONG     Type;
} EVENT_FILTER_DESCRIPTOR, *PEVENT_FILTER_DESCRIPTOR;

typedef void (*PENABLECALLBACK)(
    LPCGUID SourceId,
    ULONG IsEnabled,
    UCHAR Level,
    ULONGLONG MatchAnyKeyword,
    ULONGLONG MatchAllKeyword,
    PEVENT_FILTER_DESCRIPTOR FilterData,
    PVOID CallbackContext
);

typedef struct _RTL_BUFFER
{
    PUCHAR Buffer;
    PUCHAR StaticBuffer;
    SIZE_T Size;
    SIZE_T StaticSize;
    SIZE_T ReservedForAllocatedSize;
    PVOID ReservedForIMalloc;
} RTL_BUFFER, *PRTL_BUFFER;

typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

typedef struct _RTL_UNICODE_STRING_BUFFER
{
    UNICODE_STRING String;
    RTL_BUFFER ByteBuffer;
    UCHAR MinimumStaticBufferForTerminalNul[sizeof(WCHAR)];
} RTL_UNICODE_STRING_BUFFER, *PRTL_UNICODE_STRING_BUFFER;

typedef struct _OSVERSIONINFOA {
    DWORD dwOSVersionInfoSize;
    DWORD dwMajorVersion;
    DWORD dwMinorVersion;
    DWORD dwBuildNumber;
    DWORD dwPlatformId;
    CHAR  szCSDVersion[128];
} OSVERSIONINFOA, *POSVERSIONINFOA, *LPOSVERSIONINFOA,
    OSVERSIONINFO, *POSVERSIONINFO, *LPOSVERSIONINFO;

#define MAX_MODULE_NAME32 255

typedef struct tagMODULEENTRY32 {
    DWORD   dwSize;
    DWORD   th32ModuleID;
    DWORD   th32ProcessID;
    DWORD   GlblcntUsage;
    DWORD   ProccntUsage;
    BYTE    *modBaseAddr;
    DWORD   modBaseSize;
    HMODULE hModule;
    char    szModule[MAX_MODULE_NAME32 + 1];
    char    szExePath[MAX_PATH];
} MODULEENTRY32;

typedef struct _LSA_UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} LSA_UNICODE_STRING, *PLSA_UNICODE_STRING;

typedef struct _LSA_LAST_INTER_LOGON_INFO {
    LARGE_INTEGER LastSuccessfulLogon;
    LARGE_INTEGER LastFailedLogon;
    ULONG         FailedAttemptCountSinceLastSuccessfulLogon;
} LSA_LAST_INTER_LOGON_INFO, *PLSA_LAST_INTER_LOGON_INFO;

typedef struct _SECURITY_LOGON_SESSION_DATA {
    ULONG                     Size;
    LUID                      LogonId;
    LSA_UNICODE_STRING        UserName;
    LSA_UNICODE_STRING        LogonDomain;
    LSA_UNICODE_STRING        AuthenticationPackage;
    ULONG                     LogonType;
    ULONG                     Session;
    PSID                      Sid;
    LARGE_INTEGER             LogonTime;
    LSA_UNICODE_STRING        LogonServer;
    LSA_UNICODE_STRING        DnsDomainName;
    LSA_UNICODE_STRING        Upn;
    ULONG                     UserFlags;
    LSA_LAST_INTER_LOGON_INFO LastLogonInfo;
    LSA_UNICODE_STRING        LogonScript;
    LSA_UNICODE_STRING        ProfilePath;
    LSA_UNICODE_STRING        HomeDirectory;
    LSA_UNICODE_STRING        HomeDirectoryDrive;
    LARGE_INTEGER             LogoffTime;
    LARGE_INTEGER             KickOffTime;
    LARGE_INTEGER             PasswordLastSet;
    LARGE_INTEGER             PasswordCanChange;
    LARGE_INTEGER             PasswordMustChange;
} SECURITY_LOGON_SESSION_DATA, *PSECURITY_LOGON_SESSION_DATA;

#define LinuxFileOpen           0xFF01
#define LinuxNetworkEvent       0xFF02
#define LinuxEBPFEvent          0xFF03

#define __NR_NETWORK            400
#define __NR_PROCTERM           401
#define __NR_RAWACCESS          402
#define __NR_CREATE             403

typedef enum {
    LINUX_FO_Sid,
    LINUX_FO_ImagePath,
    LINUX_FO_PathName,
    LINUX_FO_Dir,
    LINUX_FILE_OPEN_ExtMax
} LINUX_FILE_OPEN_Extensions;

typedef struct {
    ULONGLONG           tv_sec;
    ULONG               tv_nsec;
} my_statx_timestamp;

typedef struct {
    ULONG                   m_ProcessId;
    LARGE_INTEGER           m_EventTime;
    ULONG                   m_Flags;
    ULONG                   m_Mode;
    my_statx_timestamp      m_atime;
    my_statx_timestamp      m_mtime;
    my_statx_timestamp      m_ctime;
    ULONG                   m_Extensions[LINUX_FILE_OPEN_ExtMax];
} SYSMON_LINUX_FILE_OPEN, *PSYSMON_LINUX_FILE_OPEN;


typedef struct {
    ULONG                   m_ProcessId;
    LARGE_INTEGER           m_EventTime;
    CONST VOID*             m_SockId;
    bool                    m_AddrIsIPv4;
    BYTE                    m_SrcAddr[16];
    BYTE                    m_DstAddr[16];
    WORD                    m_SrcPort;
    WORD                    m_DstPort;
    bool                    m_IsTCP;
    ULONG                   m_OldState;
    ULONG                   m_NewState;
} SYSMON_LINUX_NETWORK_EVENT, *PSYSMON_LINUX_NETWORK_EVENT;


// eBPF program load/run event - Linux only
// BPF commands from linux/bpf.h
#define BPF_CMD_PROG_LOAD       5

typedef enum {
    LINUX_EBPF_Sid,
    LINUX_EBPF_ImagePath,
    LINUX_EBPF_ProgName,
    LINUX_EBPF_ExtMax
} LINUX_EBPF_Extensions;

typedef struct {
    ULONG                   m_ProcessId;
    LARGE_INTEGER           m_EventTime;
    ULONG                   m_BpfCmd;           // BPF command (e.g., BPF_PROG_LOAD)
    ULONG                   m_ProgType;         // BPF program type
    ULONG                   m_ProgId;           // BPF program ID (returned by kernel)
    ULONG                   m_Extensions[LINUX_EBPF_ExtMax];
} SYSMON_LINUX_EBPF_EVENT, *PSYSMON_LINUX_EBPF_EVENT;




