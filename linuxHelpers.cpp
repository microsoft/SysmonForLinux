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
// linuxHelpers.cpp
//
// Linux support functions for eventsCommon.cpp
//
//====================================================================
#include "stdafx.h"
#include "rules.h"
#include "eventsCommon.h"
#include <math.h>
#include <sys/types.h>
#include <dirent.h>
#include <pwd.h>
#include <utmp.h>
#include <utmpx.h>
#include <sys/stat.h>
#include <pthread.h>
#include <sys/syscall.h>
#include <openssl/evp.h>

//--------------------------------------------------------------------
//
// InitializeCriticalSection
//
// Initialise a mutex to be used to mark critical sections for
// concurrent processing.
//
//--------------------------------------------------------------------
void
InitializeCriticalSection(
    CRITICAL_SECTION *p
    )
{
    if (p == NULL) {
        fprintf(stderr, "InitializeCriticalSection invalid params\n");
        return;
    }

    pthread_mutexattr_t a;

    if ( pthread_mutexattr_init( &a ) != 0 ) {
        fprintf( stderr, "Cannot init mutex attr\n" );
        return;
    }

    if ( pthread_mutexattr_settype( &a, PTHREAD_MUTEX_RECURSIVE ) != 0 ) {
        pthread_mutexattr_destroy( &a );
        fprintf( stderr, "Cannot set mutex attr type\n" );
        return;
    }

    if ( pthread_mutex_init( p, &a ) != 0 ) {
        fprintf( stderr, "Cannot init mutex\n" );
    }

    pthread_mutexattr_destroy( &a );
}

//--------------------------------------------------------------------
//
// EnterCriticalSection
//
// Wait for and obtain a mutex before proceeding.
//
//--------------------------------------------------------------------
void EnterCriticalSection( CRITICAL_SECTION *p ) {
    if (p == NULL) {
        fprintf(stderr, "EnterCriticalSection invalid params\n");
        return;
    }

    pthread_mutex_lock( p );
}

//--------------------------------------------------------------------
//
// TryEnterCriticalSection
//
// Tries to obtain a mutex and reports success/failure, but continues
// regardless.
//
//--------------------------------------------------------------------
bool TryEnterCriticalSection( CRITICAL_SECTION *p ) {
    if (p == NULL) {
        fprintf(stderr, "TryEnterCriticalSection invalid params\n");
        return false;
    }

    return pthread_mutex_trylock( p ) == 0;
}

//--------------------------------------------------------------------
//
// LeaveCriticalSection
//
// Releases the mutex.
//
//--------------------------------------------------------------------
void LeaveCriticalSection( CRITICAL_SECTION *p ) {
    if (p == NULL) {
        fprintf(stderr, "LeaveCriticalSection invalid params\n");
        return;
    }

    pthread_mutex_unlock( p );
}

//--------------------------------------------------------------------
//
// DeleteCriticalSection
//
// Destroys the mutex.
//
//--------------------------------------------------------------------
void DeleteCriticalSection( CRITICAL_SECTION *p ) {
    if (p == NULL) {
        fprintf(stderr, "DeleteCriticalSection invalid params\n");
        return;
    }

    // The user is responsible with preventing further access to the mutex
    pthread_mutex_destroy( p );
}

#ifdef __cplusplus
extern "C" {
#endif

extern double  g_bootSecSinceEpoch;
extern DWORD   machineId;

int     g_clkTck = 100;
size_t  g_pwEntrySize = 0;

//--------------------------------------------------------------------
//
// GetProcess
//
// Get details of a process from /proc.
//
// Returns true on success, otherwise false.
//
//--------------------------------------------------------------------
BOOLEAN GetProcess(
    PSYSMON_EVENT_HEADER Process,
    size_t Len,
    ULONG ProcessId
    )
{
    PSYSMON_PROCESS_CREATE pc = NULL;
    FILE *fp = NULL;
    char pathFile[32];
    ssize_t numRead = 0;
    char imagePath[PATH_MAX];
    char cwd[PATH_MAX];
    char cmdline[128 * 1024];
    size_t dataSize = 0;
    unsigned int imagePathLen = 0;
    unsigned int cwdLen = 0;
    unsigned int cmdlineLen = 0;
    PCHAR ptr = NULL;
    unsigned int uid = 0;
    unsigned int pts = 0;
    struct stat st;

    if (Process == NULL) {
        return false;
    }

    pc = &Process->m_EventBody.m_ProcessCreateEvent;

    //
    // Get command line, image and working directory
    //
    snprintf( pathFile, 32, "/proc/%d/cmdline", ProcessId );
    fp = fopen( pathFile, "rb" );
    if (fp == NULL) {
        return false;
    }
    numRead = fread( cmdline, 1, (128 * 1024) - 1, fp );
    fclose( fp );
    if (numRead > 0) {
        // terminate cmdline
        if (cmdline[numRead - 1] != 0x00) {
            cmdline[numRead] = 0x00;
            numRead++;
        }
        // convert nulls to spaces
        for (int i=0; i<numRead - 1; i++) {
            if (cmdline[i] == 0x00) {
                cmdline[i] = ' ';
            }
        }
    } else {
        cmdline[0] = 0x00;
    }

    snprintf( pathFile, 32, "/proc/%d/exe", ProcessId );
    numRead = readlink( pathFile, imagePath, PATH_MAX-1 );
    if (numRead > 0) {
        if (imagePath[numRead - 1] != 0x00) {
            imagePath[numRead] = 0x00;
        }
    } else {
        imagePath[0] = 0x00;
    }

    snprintf( pathFile, 32, "/proc/%d/cwd", ProcessId );
    numRead = readlink( pathFile, cwd, PATH_MAX-1 );
    if (numRead > 0) {
        if (cwd[numRead - 1] != 0x00) {
            cwd[numRead] = 0x00;
        }
    } else {
        cwd[0] = 0x00;
    }

    uid = -1;
    snprintf( pathFile, 32, "/proc/%d", ProcessId );
    if (stat( pathFile, &st ) == 0) {
        uid = st.st_uid;
    }

    imagePathLen = strlen( imagePath ) + 1;
    cwdLen = strlen( cwd ) + 1;
    cmdlineLen = strlen( cmdline ) + 1;

    // calculate extension sizes and total data size
    dataSize = sizeof( *Process ) + sizeof(uint64_t);
    if ( dataSize + imagePathLen > Len ) {
        imagePathLen = 0;
        cwdLen = 0;
        cmdlineLen = 0;
    } else {
        dataSize += imagePathLen;
        if (dataSize + cwdLen > Len ) {
            cwdLen = 0;
            cmdlineLen = 0;
        } else {
            dataSize += cwdLen;
            if ( dataSize + cmdlineLen > Len ) {
                cmdlineLen = Len - dataSize;
            }
            dataSize += cmdlineLen;
        }
    }

    Process->m_EventSize = dataSize;
    Process->m_EventType = ProcessCreate;
    Process->m_FieldFiltered = false;
    Process->m_PreFiltered = false;

    pc->m_ProcessId = ProcessId;
    GetProcessInfo( &pc->m_CreateTime.QuadPart, &pts, &pc->m_ParentProcessId,
            &pc->m_SessionId, &pc->m_ProcessKey, ProcessId );
    pc->m_AuthenticationId.LowPart = uid;
    pc->m_AuthenticationId.HighPart = pts;

    memset( pc->m_Extensions, 0, sizeof(pc->m_Extensions) );
    pc->m_Extensions[PC_Sid] = sizeof(uint64_t);
    pc->m_Extensions[PC_ImagePath] = imagePathLen;
    pc->m_Extensions[PC_CommandLine] = cmdlineLen;
    pc->m_Extensions[PC_CurrentDirectory] = cwdLen;

    ptr = (PCHAR)(pc + 1);
    *(uint64_t *)ptr = uid;
    ptr += sizeof(uint64_t);


#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wformat-truncation"
#pragma GCC diagnostic ignored "-Wstringop-overflow"
// When using snprintf, the below fields get written past the end of the sysmon event struct memory region.
// As such, source fortification (in)correctly flags the size of 'ptr' as being 0 and it fails with a buffer
// overflow. We work around this by using memcpy instead.
    if (imagePathLen > 0) {
        //snprintf( ptr, Len, "%s", imagePath );
        memcpy(ptr, imagePath, sizeof(CHAR) * imagePathLen);
        ptr += imagePathLen;
    }
    if (cmdlineLen > 0) {
        //snprintf( ptr, cmdlineLen, "%s", cmdline );
        memcpy(ptr, cmdline, sizeof(CHAR) * cmdlineLen);
        ptr += cmdlineLen;
    }
    if (cwdLen > 0) {
        //snprintf( ptr, cwdLen, "%s", cwd );
        memcpy(ptr, cwd, sizeof(CHAR) * cwdLen);
    }
 #pragma GCC diagnostic pop

    return true;
}

//--------------------------------------------------------------------
//
// SetBootTime
//
// Sets the boot time and clock tick globals
//
//--------------------------------------------------------------------
void SetBootTime()
{
    FILE *fp = NULL;
    double uptimeF = 0.0;
    char machineIdStr[9];
    struct timeval tv;

    fp = fopen( "/proc/uptime", "r" );
    if (fp != NULL) {
        if(fscanf(fp, "%lf", &uptimeF) == EOF) {
            fclose(fp);
            return;
        }

        gettimeofday(&tv, NULL);

        g_bootSecSinceEpoch = (double)tv.tv_sec + ((double)tv.tv_usec / (1000 * 1000)) - uptimeF;
        fclose(fp);
    } else {
        g_bootSecSinceEpoch = 0.0;
    }

    g_clkTck = sysconf( _SC_CLK_TCK );
    // if error, set it to the default of 100
    if (g_clkTck <= 0) {
        g_clkTck = 100;
    }

    // get passwd entry size, or guess at 4K if not
    g_pwEntrySize = sysconf( _SC_GETPW_R_SIZE_MAX );
    if (g_pwEntrySize == (size_t)-1) {
        g_pwEntrySize = 4096;
    }

    // get the machineId
    machineId = 0;
    fp = fopen( "/etc/machine-id", "r" );
    if (fp != NULL) {
        if (fread( machineIdStr, 1, 8, fp ) == 8) {
            machineIdStr[8] = 0x00;
            machineId = strtol( machineIdStr, NULL, 16 );
        }
        fclose( fp );
    }
}

//--------------------------------------------------------------------
//
// GetProcessInfo
//
// Gets the process start time in 100-ns intervals since epoch,
// pts number, process parent ID, session ID and process key
// (end_data address,
// which should a) be randomised for PIE executables and b) be
// depenedent on the size of the text segment in the executable -
// hopefully this makes it difficult to craft a process with a
// pre-determined value.)
//
// Returns true on success, otherwise false.
//
//--------------------------------------------------------------------
BOOLEAN GetProcessInfo(
    LONGLONG* StartTime,
    ULONG* Pts,
    ULONG* Ppid,
    ULONG* Sessionid,
    ULONGLONG* ProcessKey,
    ULONG Pid
    )
{
    if (StartTime == NULL || Pts == NULL || Ppid == NULL || Sessionid == NULL
            || ProcessKey == NULL) {
        fprintf(stderr, "GetProcessInfo invalid params\n");
        return FALSE;
    }

    char statFile[32];
    FILE *fp = NULL;
    char buf[2048];
    size_t numRead = 0;
    char *ptr = NULL;
    double clkTcks = 0;
    ULONG ppid = 0;
    ULONG pts = 0;
    ULONGLONG endData;

    if (Pid <= 0) {
        return FALSE;
    }

    snprintf(statFile, 32, "/proc/%d/stat", Pid);
    fp = fopen(statFile, "r");
    if (fp == NULL) {
        return FALSE;
    }

    numRead = fread(buf, 1, 2048, fp);
    buf[numRead] = 0x00;
    fclose(fp);

    //
    // extract known fields from /proc/[pid]/stat
    //
    ptr = strrchr(buf, ')');
    if (ptr == NULL) {
        return FALSE;
    }
    ptr++;
    for (int i=0; i<24; i++) {
        ptr = strchr(ptr+1, ' ');
        if (ptr == NULL) {
            return FALSE;
        }
        if (i==0) {
            sscanf(ptr, "%d", &ppid);
        } else if (i==3) {
            sscanf(ptr, "%d", &pts);
        } else if (i==18) {
            sscanf(ptr, "%lf", &clkTcks);
        }
    }
    sscanf(ptr, "%ld", &endData);

    snprintf(statFile, 32, "/proc/%d/sessionid", Pid);
    fp = fopen(statFile, "r");
    *Sessionid = -1;
    if (fp != NULL) {
        if(fscanf(fp, "%d", Sessionid) == EOF) {
            fclose(fp);
            return FALSE;
        }

        fclose(fp);
    }

    *ProcessKey = endData;
    *Pts = pts & 0xff;
    *Ppid = ppid;
    *StartTime = (LONGLONG)round(((clkTcks / g_clkTck) + g_bootSecSinceEpoch) * 1000 * 1000 * 10);
    return TRUE;
}

//--------------------------------------------------------------------
//
// GetProcessName
//
// Gets the process name into the given string.
//
// Returns true on success, otherwise false.
//
//--------------------------------------------------------------------
BOOLEAN
GetProcessName(
		 	  char* ProcName,
			  unsigned int Len,
              pid_t Pid
			  )
{
    if (ProcName == NULL) {
        fprintf(stderr, "GetProcessName invalid params\n");
        return FALSE;
    }

	char processPath[PATH_MAX];
	char *argvPtr = NULL;
	FILE *fp = NULL;
	size_t numRead = 0;
    char cmdlineFile[32] = "/proc/self/cmdline";
    char exeFile[32] = "/proc/self/exe";

    if (Len > 1) {
        *ProcName = 0x00;
    } else {
        return FALSE;
    }

    if (Pid > 0) {
        snprintf(cmdlineFile, 32, "/proc/%d/cmdline", Pid);
        snprintf(exeFile, 32, "/proc/%d/exe", Pid);
    }

	fp = fopen(cmdlineFile, "rb");
	if (fp != NULL) {
        numRead = fread(processPath, 1, PATH_MAX-1, fp);
        processPath[numRead] = 0x00;
        fclose(fp);
	}

	if (numRead <= 1) {
		numRead = readlink(exeFile, processPath, PATH_MAX-1);
        if ((int64_t)numRead <= 0) {
            return FALSE;
        }
        processPath[numRead] = 0x00;
	}

	argvPtr = strrchr(processPath, '/');
	if (argvPtr != NULL) {
		while (*argvPtr == '/') {
			argvPtr++;
		}
		if (*argvPtr == 0x00) {
			return FALSE;
		}
	} else {
		argvPtr = processPath;
	}
	snprintf(ProcName, Len, "%s", argvPtr);
	return TRUE;
}

//--------------------------------------------------------------------
//
// StrIsNum
//
// Returns true if string s is a number, otherwise false.
//
//--------------------------------------------------------------------
BOOLEAN StrIsNum(
    const char *s
    )
{
    if (s == NULL || *s == 0x00) {
        return false;
    }

    while (*s != 0x00) {
        if (!isdigit(*s)) {
            return false;
        }
        s++;
    }
    return true;
}

//--------------------------------------------------------------------
//
// EnumProcesses
//
// Reimplementation of Windows EnumProcesses. Returns an array of
// process IDs. cb specifies size of array in bytes. lpcbNeeded
// returns number of bytes used.
//
// Returns true on success, otherwise false.
//
//--------------------------------------------------------------------
BOOLEAN EnumProcesses(
    PDWORD      lpidProcess,
    DWORD       cb,
    PDWORD      lpcbNeeded
    )
{
    if (lpidProcess == NULL || lpcbNeeded == NULL) {
        fprintf(stderr, "EnumProcesses invalid params\n");
        return false;
    }

    DIR *directory;
    struct dirent *entry;
    DWORD count = 0;

    *lpcbNeeded = 0;

    directory = opendir("/proc");
    if (directory == NULL) {
        return false;
    }

    while ((entry = readdir( directory )) != NULL && *lpcbNeeded < cb) {
        if (entry->d_type == DT_DIR && StrIsNum(entry->d_name)) {
            lpidProcess[count++] = atoi(entry->d_name);
            (*lpcbNeeded) += sizeof(DWORD);
        }
    }

    closedir(directory);
    return true;
}

//--------------------------------------------------------------------
//
// StringFromGUID2
//
// Reimplmentation of Windows StringFromGUID2. Makes a string of the
// provided GUID.
//
// Returns number of characters (including null).
//
//--------------------------------------------------------------------
int StringFromGUID2(
    const GUID guid,
    PCHAR      lpsz,
    int        cchMax
    )
{
    if (lpsz == NULL) {
        fprintf(stderr, "STringFromGUID2 invalid params\n");
        return 0;
    }

    // target string size includes enclosing braces, hyphens, and null terminator
    int size = (sizeof(guid.Data1) + sizeof(guid.Data2) + sizeof(guid.Data3) +
            sizeof(guid.Data4)) * 2 + 2 + 4 + 1;

    if (cchMax < size) {
        return 0;
    }

    return 1 + snprintf(lpsz, cchMax, "{%08x-%04hx-%04hx-%02hhx%02hhx-%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx}",
            guid.Data1, guid.Data2, guid.Data3, guid.Data4[0], guid.Data4[1],
            guid.Data4[2], guid.Data4[3], guid.Data4[4], guid.Data4[5],
            guid.Data4[6], guid.Data4[7]);

}

//--------------------------------------------------------------------
//
// GetLogonTime
//
// Return the logon time, in 100ns intervals since epoch, for given
// user and terminal. LUID->LowPart = uid; LUID->HighPart = #pts
//
//--------------------------------------------------------------------
LARGE_INTEGER GetLogonTime(
    CONST LUID* user_luid
    )
{
    LARGE_INTEGER result = {{0}};
    if (user_luid == NULL) {
        fprintf(stderr, "GetLogonTime invalid params\n");
        return result;
    }

    struct passwd pwd;
    struct passwd *entry = NULL;
    char buf[g_pwEntrySize];
    struct utmpx *r;
    struct utmpx s;

    getpwuid_r( user_luid->LowPart, &pwd, buf, g_pwEntrySize, &entry );
    if (entry == NULL) {
        return result;
    }

    snprintf( s.ut_line, UT_LINESIZE, "pts/%d", user_luid->HighPart );

    setutxent();
    while ((r = getutxline(&s)) != (struct utmpx *)NULL) {
        if (strncmp(r->ut_user, pwd.pw_name, __UT_NAMESIZE) == 0) {
            // time since epoch in 100ns intervals
            result.QuadPart = ((uint64_t)r->ut_tv.tv_sec * 1000 * 1000 * 10) + ((uint64_t)r->ut_tv.tv_usec * 10);
            break;
        }
    }

    endutxent();
    return result;
}

//--------------------------------------------------------------------
//
// TranslateSid
//
// Reimplementation of Windows TranslateSid. Converts given UID,
// provided as a SID, to the associated username.
//
//--------------------------------------------------------------------
void TranslateSid(
    CONST PSID  pUserSid,
    PTCHAR      Buffer,
    SIZE_T      Size
    )
{
    if (Buffer != NULL) {
        *Buffer = 0x00;
    }

    if (pUserSid == NULL || Buffer == NULL) {
        return;
    }

    struct passwd pwd;
    struct passwd *entry = NULL;
    char buf[g_pwEntrySize];

    getpwuid_r( (uid_t)*pUserSid, &pwd, buf, g_pwEntrySize, &entry );
    if (entry == NULL) {
        return;
    }

    snprintf(Buffer, Size, "%s", pwd.pw_name);
}

//--------------------------------------------------------------------
//
// EventDataDescCreate
//
// Linux implementation of EventDataDescCreate
//
//--------------------------------------------------------------------
VOID EventDataDescCreate(
       _In_ PEVENT_DATA_DESCRIPTOR EventDataDescriptor,
       _In_ const PVOID            DataPtr,
       _In_ ULONG                  DataSize
       )
{
    if (EventDataDescriptor == NULL || DataPtr == NULL) {
        return;
    }
    EventDataDescriptor->Ptr = (ULONGLONG)strdup((PCHAR)DataPtr);
    EventDataDescriptor->Size = DataSize;
    EventDataDescriptor->Reserved = 1;
}

//--------------------------------------------------------------------
//
// GetSystemTimeAsLargeInteger
//
// Gets the time since epoch in 100ns intervals
//
//--------------------------------------------------------------------
VOID GetSystemTimeAsLargeInteger(
    PLARGE_INTEGER timestamp
    )
{
    if (timestamp == NULL) {
        fprintf(stderr, "GetSystemTimeAsLargeInteger invalid params\n");
        return;
    }

    struct timeval tv;

    gettimeofday(&tv, NULL);
    // time in 100ns intervals since epoch
    timestamp->QuadPart = (tv.tv_sec * 1000 * 1000 * 10) + (tv.tv_usec * 10);
}

//--------------------------------------------------------------------
//
// LargeTimeToSeconds
//
// Returns time in seconds since epoch of supplied timestamp (in 100ns
// intervals since epoch).
//
//--------------------------------------------------------------------
time_t LargeTimeToSeconds(
    CONST PLARGE_INTEGER timestamp
    )
{
    if (timestamp == NULL) {
        fprintf(stderr, "LargeTimeToSeconds invalid params\n");
        return (time_t)0;
    }

    return (time_t)(timestamp->QuadPart / (1000 * 1000 * 10));
}

//--------------------------------------------------------------------
//
// LargeTimeMilliseconds
//
// Returns the number of millisecond component of a LARGE_INTEGER
// time.
//
//--------------------------------------------------------------------
unsigned int LargeTimeMilliseconds(
    CONST PLARGE_INTEGER timestamp
    )
{
    if (timestamp == NULL) {
        fprintf(stderr, "LargeTimeMilliseconds invalid params\n");
        return 0;
    }

    return (unsigned int)((timestamp->QuadPart / (1000 * 10)) % 1000);
}

//--------------------------------------------------------------------
//
// LargeTimeNanoseconds
//
// Returns the number of nanosecond component of a LARGE_INTEGER time.
//
//--------------------------------------------------------------------
unsigned int LargeTimeNanoseconds(
    CONST PLARGE_INTEGER timestamp
    )
{
    if (timestamp == NULL) {
        fprintf(stderr, "LargeTimeNanoseconds invalid params\n");
        return 0;
    }

    return (unsigned int)((timestamp->QuadPart % (1000 * 1000 * 10)) * 100);
}

//--------------------------------------------------------------------
//
// LinuxFileTimeToLargeInteger
//
// Converts linux file time to LARGE_INTEGER time.
//
//--------------------------------------------------------------------
VOID LinuxFileTimeToLargeInteger(
    PLARGE_INTEGER timestamp,
    const my_statx_timestamp *filetime
    )
{
    if (timestamp != NULL) {
        timestamp->QuadPart = 0;
    }

    if (timestamp == NULL || filetime == NULL) {
        fprintf(stderr, "LinuxFileTimeToLargeInteger invalid params\n");
        return;
    }

    timestamp->QuadPart = (filetime->tv_sec * 1000 * 1000 * 10) + (filetime->tv_nsec / 100);
}

//--------------------------------------------------------------------
//
// LargeIntegerToSystemTimeString
//
// Converts linux file time to LARGE_INTEGER time.
//
//--------------------------------------------------------------------
VOID LargeIntegerToSystemTimeString(
    char *s,
    size_t sLen,
    CONST PLARGE_INTEGER timestamp
    )
{
    if (s != NULL) {
        *s = 0x00;
    }

    if (s == NULL || timestamp == NULL) {
        fprintf(stderr, "LargeIntegerToSystemTimeString invalid params\n");
        return;
    }

    // time in 100ns intervals since epoch
    struct tm timeFields;
    time_t fileTime = LargeTimeToSeconds( timestamp );

    if ( gmtime_r(&fileTime, &timeFields) ) {

        snprintf( s, sLen, "%04u-%02u-%02uT%02u:%02u:%02u.%09uZ",
                timeFields.tm_year + 1900, timeFields.tm_mon + 1, timeFields.tm_mday,
                timeFields.tm_hour, timeFields.tm_min, timeFields.tm_sec,
                LargeTimeNanoseconds( timestamp ));
    } else {

        snprintf( s, sLen, "Incorrect filetime: 0x%" PRIx64,
                     timestamp->QuadPart );
    }
}

//--------------------------------------------------------------------
//
// LinuxGetFileHash
//
// Calculates image hash.
//
//--------------------------------------------------------------------
void LinuxGetFileHash(uint32_t hashType, PTCHAR imagePath, char *stringBuffer, size_t stringBufferSize)
{
    unsigned char       tmpReadBuffer[4096] = {};
    unsigned char       tmpHashBuffer[ALGO_MAX][256] = {};
    unsigned char       tmpHashPrefixBuffer[16] = {};
    unsigned char       tmpStringBuffer[256] = {};
    char                hashSeparator[] = ",";
    char                hashPrefix[3][8] = {"SHA1=", "MD5=", "SHA256="};
    unsigned int        hashSize[ALGO_MAX] = {};
    unsigned int        hashFlag[ALGO_MAX] = {};
    size_t              n;
    FILE                *filePtr;
    EVP_MD_CTX          *sha1_ctx, *md5_ctx, *sha256_ctx;

    // Allocate digests context
    sha1_ctx    = EVP_MD_CTX_new();
    md5_ctx     = EVP_MD_CTX_new();
    sha256_ctx  = EVP_MD_CTX_new();
    if ( !sha1_ctx || !md5_ctx || !sha256_ctx ) {
        if(!sha1_ctx) EVP_MD_CTX_free(sha1_ctx);
        if(!md5_ctx) EVP_MD_CTX_free(md5_ctx);
        if(!sha256_ctx) EVP_MD_CTX_free(sha256_ctx);
        return;
    }

    EVP_DigestInit(sha1_ctx  , EVP_sha1()); // CodeQL [SM02689] SHA1 use is intentional here, Sysmon needs it for historical reasons
    EVP_DigestInit(md5_ctx   , EVP_md5());  // CodeQL [SM02689] MD5 use is intentional here, Sysmon needs it for historical reasons
    EVP_DigestInit(sha256_ctx, EVP_sha256());

    hashFlag[ALGO_SHA1] = (((hashType>>(ALGO_SHA1-1))&1) && (hashType & ALGO_MULTIPLE)) || (hashType == ALGO_SHA1);
    hashFlag[ALGO_MD5] = (((hashType>>(ALGO_MD5-1))&1) && (hashType & ALGO_MULTIPLE)) || (hashType == ALGO_MD5);
    hashFlag[ALGO_SHA256] = (((hashType>>(ALGO_SHA256-1))&1) && (hashType & ALGO_MULTIPLE)) || (hashType == ALGO_SHA256);

    filePtr = fopen(imagePath, "rb");
    if( !filePtr ) {
        EVP_MD_CTX_free(sha1_ctx);
        EVP_MD_CTX_free(md5_ctx);
        EVP_MD_CTX_free(sha256_ctx);
        return;
    }

    // Read and hash image
    while((n = fread(tmpReadBuffer, 1, sizeof(tmpReadBuffer), filePtr))){

        if( hashFlag[ALGO_SHA1] ){
            if (!EVP_DigestUpdate(sha1_ctx, tmpReadBuffer, n)){
                fclose(filePtr);
                EVP_MD_CTX_free(sha1_ctx);
                EVP_MD_CTX_free(md5_ctx);
                EVP_MD_CTX_free(sha256_ctx);
                return;
            }
            if ( !(hashType & ALGO_MULTIPLE) ) continue;
        }

        if( hashFlag[ALGO_MD5] ){
            if (!EVP_DigestUpdate(md5_ctx, tmpReadBuffer, n)){
                fclose(filePtr);
                EVP_MD_CTX_free(sha1_ctx);
                EVP_MD_CTX_free(md5_ctx);
                EVP_MD_CTX_free(sha256_ctx);
                return;
            }
            if ( !(hashType & ALGO_MULTIPLE) ) continue;
        }

        if( hashFlag[ALGO_SHA256] ){
            if (!EVP_DigestUpdate(sha256_ctx, tmpReadBuffer, n)){
                fclose(filePtr);
                EVP_MD_CTX_free(sha1_ctx);
                EVP_MD_CTX_free(md5_ctx);
                EVP_MD_CTX_free(sha256_ctx);
                return;
            }
            if ( !(hashType & ALGO_MULTIPLE) ) continue;
        }

    }
    fclose(filePtr);

    // Retrieve digest and cleanup
    EVP_DigestFinal(sha1_ctx  , tmpHashBuffer[ALGO_SHA1]  , &hashSize[ALGO_SHA1]);
    EVP_DigestFinal(md5_ctx   , tmpHashBuffer[ALGO_MD5]   , &hashSize[ALGO_MD5]);
    EVP_DigestFinal(sha256_ctx, tmpHashBuffer[ALGO_SHA256], &hashSize[ALGO_SHA256]);

    memset(tmpStringBuffer, 0, sizeof(tmpStringBuffer));
    memset(tmpHashPrefixBuffer, 0, sizeof(tmpHashPrefixBuffer));

    for(unsigned int algo=0;algo<ALGO_MAX;algo++){
        if( hashFlag[algo] ){

            // Add seperator if multiple hashes
            if( *tmpStringBuffer ){
                memset(tmpStringBuffer, 0, sizeof(tmpStringBuffer));
                memset(tmpHashPrefixBuffer, 0, sizeof(tmpHashPrefixBuffer));

                strcat((char *)tmpHashPrefixBuffer, hashSeparator);
            }

            // Add hash prefix "SHA1=", "MD5=" or "SHA256="
            switch(algo){
                case ALGO_SHA1:
                    strcat((char *)tmpHashPrefixBuffer, hashPrefix[ALGO_SHA1-1]);
                    break;
                case ALGO_MD5:
                    strcat((char *)tmpHashPrefixBuffer, hashPrefix[ALGO_MD5-1]);
                    break;
                case ALGO_SHA256:
                    strcat((char *)tmpHashPrefixBuffer, hashPrefix[ALGO_SHA256-1]);
                    break;
            }

            // Digest to hex
            for(unsigned int i=0;i<hashSize[algo];i++){
                snprintf((char *)tmpStringBuffer+i*2, sizeof(tmpStringBuffer), "%02x", tmpHashBuffer[algo][i]);
            }

            if(stringBufferSize > strnlen((char *)tmpHashPrefixBuffer, sizeof(tmpHashPrefixBuffer)) + strnlen((char *)tmpStringBuffer, sizeof(tmpStringBuffer))){
                strcat(stringBuffer, (char *)tmpHashPrefixBuffer);
                strcat(stringBuffer, (char *)tmpStringBuffer);
            }

            if( !(hashType & ALGO_MULTIPLE) ) {
                EVP_MD_CTX_free(sha1_ctx);
                EVP_MD_CTX_free(md5_ctx);
                EVP_MD_CTX_free(sha256_ctx);
                return;
            }
        }
    }
}

//--------------------------------------------------------------------
//
// GetTid
//
// Returns current process thread id.
//
//--------------------------------------------------------------------
pid_t GetTid()
{
	return syscall(SYS_gettid);
}


#ifdef __cplusplus
}
#endif

