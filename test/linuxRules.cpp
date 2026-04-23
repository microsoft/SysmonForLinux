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
// linuxRules.cpp
//
// Tests for Sysmon For Linux functions.
//
//====================================================================

// UnitTests for rule engine and configuration parsing - Linux additions
#include "test.h"
#include "linuxHelpers.h"

#include <glob.h>
#include <string>
#include <vector>
#include <unistd.h>
#include <sys/types.h>
#include <signal.h>
#include <sys/time.h>
#include <pwd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/syscall.h>
extern "C" {
#include "outputxml.h"
}
#include "structs.h"
#include "hexdump.h"

extern PTCHAR SYSMONEVENT_CREATE_PROCESS_FieldNames[];

PCSTR testDefaultVersion = "4.50";

uint64_t *eventIdAddr = (uint64_t *)MAP_FAILED;

double g_bootSecSinceEpoch = 0;

BOOLEAN g_DebugMode = FALSE;
BOOLEAN g_DebugModeVerbose = FALSE;
CRITICAL_SECTION g_DebugModePrintCriticalSection;

// Test wide string functions on Linux only
typedef struct
{
    CONST WCHAR str1[16];
    CONST WCHAR str2[16];
    CONST size_t str1len;
    CONST size_t str2len;
    CONST bool strEqual;
    CONST bool strCaseEqual;
    CONST size_t charsEqual;
    CONST size_t caseCharsEqual;
    CONST WCHAR includeChar;
    CONST size_t includeFirstPos;
    CONST size_t includeLastPos;
    CONST WCHAR excludeChar;
    CONST WCHAR includeSubStr[16];
    CONST size_t includeSubStrPos;
    CONST WCHAR excludeSubStr[16];
    CONST WCHAR includeCharSet[16];
    CONST size_t notIncludeCharSetPos;
    CONST WCHAR excludeCharSet[16];
    CONST WCHAR upper;
    CONST WCHAR lower;
} WideStringTests;

typedef struct
{
    CONST CHAR utf8str[32];
    CONST WCHAR utf16str[32];
    CONST size_t utf8count;
    CONST size_t utf16count;
} WideStringConvTests;


// WideString tests the wide string functions in linuxWideChar.c
TEST( Rules, WideString )
{
    CONST WideStringTests WideStrings[] = {
        { {'h', 'e', 'L', 'L', 'o', 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10},
          {'h', 'e', 'L', 'L', 'o', 0, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20},
          5, 5, true, true, 5, 5, 'L', 2, 3, 'P',
          {'e', 'L', 0, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33},
          1,
          {'n', 'o', 0, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46},
          {'L', 'e', 'h', 0, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58},
          4,
          {'t', 'W', 0, 59, 60, 61, 62, 63, 64, 65, 66, 67, 68, 69, 70, 71},
          'M', 'm' },

        { {'h', 'e', 'L', 'L', 'o', 0, 72, 73, 74, 75, 76, 77, 78, 79, 80, 81},
          {'H', 'E', 'l', 'l', 'O', 0, 82, 83, 84, 85, 86, 87, 88, 89, 90, 91},
          5, 5, false, true, 0, 5, 'e', 1, 1, 'P',
          {'h', 'e', 0, 92, 93, 94, 95, 96, 97, 98, 99, 100, 101, 102, 103, 104},
          0,
          {'n', 'o', 0, 105, 106, 107, 108, 109, 110, 111, 112, 113, 114, 115, 116, 117},
          {'e', 'h', 0, 118, 119, 120, 121, 122, 123, 124, 125, 126, 127, 128, 129, 130},
          2,
          {'t', 'W', 0, 131, 132, 133, 134, 135, 136, 137, 138, 139, 140, 141, 142, 143},
          'Z', 'z' },

        { {'h', 'e', 'L', 'L', 'o', 0, 144, 145, 146, 147, 148, 149, 150, 151, 152, 153},
          {'h', 'e', 'L', 'p', 0, 154, 155, 156, 157, 158, 159, 160, 161, 162, 163, 164},
          5, 4, false, false, 3, 3, 'h', 0, 0, 'P',
          {'L', 'o', 0, 165, 166, 167, 168, 169, 170, 171, 172, 173, 174, 175, 176, 177},
          3,
          {'n', 'o', 0, 178, 179, 180, 181, 182, 183, 184, 185, 186, 187, 188, 189, 190},
          {'h', 0, 191, 192, 193, 194, 195, 196, 197, 198, 199, 200, 201, 202, 203, 204},
          1,
          {'t', 'W', 0, 205, 206, 207, 208, 209, 210, 211, 212, 213, 214, 215, 216, 217},
          'A', 'a' },

        { {'h', 'e', 'L', 'L', 'o', 0, 218, 219, 220, 221, 222, 223, 224, 225, 226, 227},
          {'H', 'E', 'l', 0, 228, 229, 230, 231, 232, 233, 234, 235, 236, 237, 238, 239},
          5, 3, false, false, 0, 3, 'o', 4, 4, 'P',
          {'o', 0, 240, 241, 242, 243, 244, 245, 246, 247, 248, 249, 250, 251, 252, 253},
          4,
          {'n', 'o', 0, 254, 255, 256, 257, 258, 259, 260, 261, 262, 263, 264, 265, 266},
          {'e', 'h', 'L', 'o', 0, 267, 268, 269, 270, 271, 272, 273, 274, 275, 276, 277},
          5,
          {'t', 'W', 0, 278, 279, 280, 281, 282, 283, 284, 285, 286, 287, 288, 289, 290},
          'G', 'g' }
    };

    CONST WideStringConvTests WideConv[] = {
        { "hello", {'h', 'e', 'l', 'l', 'o', 0}, 6, 6 },
        { "1 \xcb\x86 1", {'1', ' ', 0x02c6, ' ', '1', 0}, 7, 6 },
        { "2 \xc2\x90", {'2', ' ', 0x0090, 0}, 5, 4 },
        { "\xe0\xa3\xbf 3", {0x08ff, ' ', '3', 0}, 6, 4 },
        { "\xf0\x92\x8d\x85", {0xd808, 0xdf45, 0}, 5, 3 },
        { "\xf0\x92\x8d\x85\xe0\xa3\xbf", {0xd808, 0xdf45, 0x08ff, 0}, 8, 4 },
        { "\xf0\x92\x8d\x85 ", {0xd808, 0xdf45, ' ', 0}, 6, 4 },
        { " \xf0\x92\x8d\x85 ", {' ', 0xd808, 0xdf45, ' ', 0}, 7, 5 },
        { "\xc2\x90\xf0\x92\x8d\x85 ", {0x0090, 0xd808, 0xdf45, ' ', 0}, 8, 5 }
    };

    for( auto CONST& test : WideStrings ) {
        EXPECT_EQ( WideStrlen( test.str1 ), test.str1len );
        EXPECT_EQ( WideStrlen( test.str2 ), test.str2len );
        EXPECT_EQ( WideStrcmp( test.str1, test.str2 ) == 0, test.strEqual );
        EXPECT_EQ( WideStrcasecmp( test.str1, test.str2 ) == 0, test.strCaseEqual );
        EXPECT_EQ( WideStrncmp( test.str1, test.str2, test.charsEqual ), 0 );
        if (test.charsEqual < test.str1len && test.charsEqual < test.str2len) {
            EXPECT_EQ( WideStrncmp( test.str1, test.str2, test.charsEqual + 1 ) != 0, true );
        }
        EXPECT_EQ( WideStrncasecmp( test.str1, test.str2, test.caseCharsEqual ), 0 );
        if (test.caseCharsEqual < test.str1len && test.caseCharsEqual < test.str2len) {
            EXPECT_EQ( WideStrncasecmp( test.str1, test.str2, test.caseCharsEqual + 1 ) != 0, true );
        }
        PCWSTR first = WideStrchr( (PWCHAR)test.str1, test.includeChar );
        PCWSTR last = WideStrrchr( (PWCHAR)test.str1, test.includeChar );
        EXPECT_EQ( first != NULL, true );
        EXPECT_EQ( last != NULL, true );
        EXPECT_EQ( first - test.str1, test.includeFirstPos );
        EXPECT_EQ( last - test.str1, test.includeLastPos );
        EXPECT_EQ( WideStrchr( test.str1, test.excludeChar ), (PWCHAR)NULL );
        EXPECT_EQ( WideStrrchr( (PWCHAR)test.str1, test.excludeChar ), (PWCHAR)NULL );
        PCWSTR substr = WideStrstr( (PWCHAR)test.str1, test.includeSubStr );
        EXPECT_EQ( substr != NULL, true );
        EXPECT_EQ( substr - test.str1, test.includeSubStrPos );
        EXPECT_EQ( WideStrstr( (PWCHAR)test.str1, test.excludeSubStr ), (PWCHAR)NULL );
        const size_t notCharsetPos = WideStrspn( test.str1, test.includeCharSet );
        EXPECT_EQ( notCharsetPos, test.notIncludeCharSetPos );
        EXPECT_EQ( WideStrspn( test.str1, test.excludeCharSet ), 0 );
        EXPECT_EQ( test.upper, WideToupper( test.lower ) );
        EXPECT_EQ( test.lower, WideTolower( test.upper ) );
    }

    for( auto CONST& conv : WideConv ) {
        CHAR utf8[32];
        WCHAR utf16[32];
        EXPECT_EQ( UTF8toUTF16( NULL, conv.utf8str, 0 ), conv.utf16count );
        EXPECT_EQ( UTF8toUTF16( utf16, conv.utf8str, 32 ), conv.utf16count );
        EXPECT_EQ( WideStrcmp( conv.utf16str, utf16 ), 0 );
        EXPECT_EQ( UTF16toUTF8( NULL, conv.utf16str, 0 ), conv.utf8count );
        EXPECT_EQ( UTF16toUTF8( utf8, conv.utf16str, 32 ), conv.utf8count );
        EXPECT_EQ( strcmp( (PCHAR)conv.utf8str, (PCHAR)utf8 ), 0 );
    }
}

typedef struct {
    const char* exe;
    const char* cmdline;
    const int len;
    const char* match;
} ProcessNameTests;

// ProcessName tests the GetProcessName function in linuxHelpers.cpp
TEST( Process, ProcessName )
{
    char pName[128];
    pid_t child = 0;
    char** cmdline;
    unsigned int numspaces = 0;
    char *ptr = NULL;
    char* cmdline_copy = NULL;

    // the process name is first fetched from the command line, falling
    // back to what the image file points at
    CONST ProcessNameTests pTests[] = {
        { "./mysleep", "/a/b/alias 500 1 2 3 4 5", 128, "alias" },
        { "./mysleep", "/a/b/alias", 128, "alias" },
        { "./mysleep", "alias 500", 128, "alias" },
        { "./mysleep", "alias", 128, "alias" },
        { "./mysleep", NULL, 128, "mysleep" },
        { "./yoursleep", NULL, 128, "mysleep" },
        { "./mysleep", NULL, 4, "mys" },
        { "./mysleep", "/a/b/alias 500 1 2 3 4 5", 3, "al" },
    };

    for ( auto CONST test : pTests ) {

        cmdline = NULL;
        cmdline_copy = NULL;

        if (test.cmdline != NULL) {
            // expand cmdline string into array of strings
            numspaces = 0;
            cmdline_copy = strdup(test.cmdline);
            EXPECT_NE(cmdline_copy, nullptr);
            ptr = cmdline_copy;
            while ((ptr = strchr(ptr, ' ')) != NULL) {
                numspaces++;
                ptr++;
            }

            cmdline = (char**)malloc((numspaces+2) * sizeof(char*));
            ptr = cmdline_copy;
            for (unsigned int i=0; i<numspaces+1; i++) {
                cmdline[i] = ptr;
                ptr = strchr(ptr, ' ');
                if (ptr != NULL) {
                    *ptr = 0x00;
                    ptr++;
                }
            }
            cmdline[numspaces+1] = 0x00;
        } else {
            cmdline = NULL;
        }

        child = fork();

        // We are not using the GTEST ASSERT_* here as the static analysis seems to think that
        // its possible to have a memory leak. We explicitly check the value and free memory
        // that the analyzer is complaining about and then ASSERT.
        if (child < 0)
        {
            free(cmdline);
            free(cmdline_copy);
            cmdline = NULL;
            cmdline_copy = NULL;
            ASSERT_TRUE(false);
        }

        if (child == 0) {
            execve( test.exe, (char* const*)cmdline, NULL );
        }

        usleep(10000);
        EXPECT_TRUE( GetProcessName( pName, test.len, child ) );
        EXPECT_EQ( strcmp( pName, test.match ), 0 );

        kill( child, 9 );

        if (cmdline != NULL) {
            free(cmdline);
        }
        if (cmdline_copy != NULL) {
            free(cmdline_copy);
        }
    }
}

// fetchSessionId get the session identifier for the process. If CONFIG_AUDIT is not set, return -1 as Sysmon would.
ULONG fetchSessionId( pid_t ProcessId )
{
    ULONG sessionId;
    FILE *fp;
    char filename[32];

    snprintf( filename, 32, "/proc/%d/sessionid", ProcessId );
    fp = fopen( filename, "r" );
    if( fp == NULL ) {

        return -1;
    }

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-result"
    fscanf( fp, "%d", &sessionId );
#pragma GCC diagnostic pop
    fclose( fp );

    return sessionId;
}

// ProcessInfo tests the GetProcessInfo function in linuxHelpers.cpp
TEST( Process, ProcessInfo )
{
    pid_t child = 0;
    struct timeval tv;
    LONGLONG timeinseconds = 0;
    LONGLONG startTime = 0;
    ULONG pts = 0;
    ULONG ppid = 0;
    const pid_t myPid = getpid();
    ULONG sessionId = 0;
    ULONGLONG processKeys[10];
    char mysleep[] = "./mysleep";
    char* args[2] = { mysleep, NULL };

    SetBootTime();

    for (unsigned int i=0; i<10; i++) {
        child = fork();
        ASSERT_TRUE(child >= 0);
        if (child == 0) {
            execve( mysleep, args, NULL );
        }

        gettimeofday( &tv, NULL );
        timeinseconds = tv.tv_sec + (tv.tv_usec > 500000 ? 1 : 0);

        usleep(10000);
        EXPECT_TRUE( GetProcessInfo( &startTime, &pts, &ppid, &sessionId, &processKeys[i], child ) );
        // startTime is in 100ns intervals, allow a second leeway
        EXPECT_TRUE( abs(timeinseconds - (startTime / (1000 * 1000 * 10))) <= 1 );
        EXPECT_EQ( ppid, myPid );
        EXPECT_EQ( sessionId, fetchSessionId( child ) );
        // check if process keys are unique
        for (unsigned int j=0; j<i; j++) {
            EXPECT_TRUE( processKeys[i] != processKeys[j] );
        }
    }
}

typedef struct {
    const char* cwd;
    const char* exepath;
    const char* cmdline;
    const unsigned int len;
    const char* storedExe;
    const char* storedCwd;
    const char* storedCmdline;
} GetProcessTests;

// GetProcess tests the GetProcess function in linuxhelpers.cpp
TEST( Process, GetProcess )
{
    pid_t child = 0;
    struct timeval tv;
    LONGLONG timeinseconds = 0;
    CONST pid_t myPid = getpid();
    unsigned int i = 0;
    unsigned int count = 0;
    char systemCmd[PATH_MAX * 2];
    char exepath[PATH_MAX];
    char** cmdline;
    unsigned int numspaces = 0;
    char *ptr = NULL;
    char* cmdline_copy = NULL;
    PSYSMON_PROCESS_CREATE pc = NULL;

    SetBootTime();

    GetProcessTests pTests[] = {
        { "/tmp/sysmon_test_1234567", "/tmp/sysmon_exe_1234567", "abc def ghi", sizeof(SYSMON_EVENT_HEADER) + 1024,
          "/tmp/sysmon_exe_1234567/mysleep", "/tmp/sysmon_test_1234567", "abc def ghi" },
        { "/tmp/sysmon_test_1234567", "/tmp/sysmon_exe_1234567", "abc def ghi", sizeof(SYSMON_EVENT_HEADER) + 61,
          "/tmp/sysmon_exe_1234567/mysleep", "/tmp/sysmon_test_1234567", "abc" },
        { "/tmp/sysmon_test_1234567", "/tmp/sysmon_exe_1234567", "abc def ghi", sizeof(SYSMON_EVENT_HEADER) + 57,
          "/tmp/sysmon_exe_1234567/mysleep", "/tmp/sysmon_test_1234567", NULL },
    };

    count = sizeof(pTests) / sizeof(*pTests);
    ULONGLONG processKeys[count];

    for ( auto CONST test : pTests ) {
        char data[test.len];
        PSYSMON_EVENT_HEADER process = (PSYSMON_EVENT_HEADER)data;
        if (test.cmdline != NULL) {
            // expand cmdline string into array of strings
            numspaces = 0;
            cmdline_copy = strdup(test.cmdline);
            EXPECT_NE(cmdline_copy, nullptr);
            ptr = cmdline_copy;
            while ((ptr = strchr(ptr, ' ')) != NULL) {
                numspaces++;
                ptr++;
            }

            cmdline = (char**)malloc((numspaces+2) * sizeof(char*));
            ptr = cmdline_copy;
            for (unsigned int k=0; k<numspaces+1; k++) {
                cmdline[k] = ptr;
                ptr = strchr(ptr, ' ');
                if (ptr != NULL) {
                    *ptr = 0x00;
                    ptr++;
                }
            }
            cmdline[numspaces+1] = 0x00;
        } else {
            cmdline = NULL;
        }

        mkdir(test.cwd, 0777);
        mkdir(test.exepath, 0777);
        snprintf(exepath, PATH_MAX, "%s/mysleep", test.exepath);
        snprintf(systemCmd, PATH_MAX * 2, "cp mysleep %s", exepath);

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-result"
        system(systemCmd);
#pragma GCC diagnostic pop

        child = fork();

        // We are not using the GTEST ASSERT_* here as the static analysis seems to think that
        // its possible to have a memory leak. We explicitly check the value and free memory
        // that the analyzer is complaining about and then ASSERT.
        if (child < 0)
        {
            free(cmdline);
            cmdline = NULL;
            ASSERT_TRUE(false);
        }

        if (child == 0) {
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-result"
            chdir(test.cwd);
#pragma GCC diagnostic pop
            execve( exepath, cmdline, NULL );
        }

        gettimeofday( &tv, NULL );
        timeinseconds = tv.tv_sec + (tv.tv_usec > 500000 ? 1 : 0);

        usleep(10000);
        EXPECT_TRUE( GetProcess( process, test.len, child ) );
        pc = &process->m_EventBody.m_ProcessCreateEvent;
        EXPECT_EQ( process->m_EventType, ProcessCreate );
        EXPECT_EQ( pc->m_ProcessId, child );
        // startTime is in 100ns intervals, allow a second leeway
        EXPECT_TRUE( abs(timeinseconds - (pc->m_CreateTime.QuadPart / (1000 * 1000 * 10))) <= 1 );
        EXPECT_EQ( pc->m_ParentProcessId, myPid );
        EXPECT_EQ( pc->m_SessionId, fetchSessionId( child ) );
        // check if process keys are unique
        processKeys[i] = pc->m_ProcessKey;
        for (unsigned int j=0; j<i; j++) {
            EXPECT_TRUE( processKeys[i] != processKeys[j] );
        }
        // data fits in available memory
        EXPECT_TRUE( process->m_EventSize <= test.len );

        // check extensions
        ptr = (char *)(pc + 1);
        unsigned int dataSize = sizeof(SYSMON_EVENT_HEADER);
        unsigned int exSize = 0;
        if (pc->m_Extensions[PC_Sid] != 0) {
            exSize = sizeof(uint64_t);
            EXPECT_EQ( pc->m_Extensions[PC_Sid], exSize );
            EXPECT_EQ( *(uint64_t *)ptr, getuid() );
            dataSize += exSize;
            ptr += exSize;
        }

        if (pc->m_Extensions[PC_ImagePath] != 0) {
            exSize = strlen(ptr) + 1;
            EXPECT_EQ( pc->m_Extensions[PC_ImagePath], exSize );
            EXPECT_EQ( strcmp( ptr, test.storedExe ), 0 );
            dataSize += exSize;
            ptr += exSize;
        }

        if (pc->m_Extensions[PC_CommandLine] != 0) {
            exSize = strlen(ptr) + 1;
            EXPECT_EQ( pc->m_Extensions[PC_CommandLine], exSize );
            EXPECT_EQ( strcmp( ptr, test.storedCmdline ), 0 );
            dataSize += exSize;
            ptr += exSize;
        }

        if (pc->m_Extensions[PC_CurrentDirectory] != 0) {
            exSize = strlen(ptr) + 1;
            EXPECT_EQ( pc->m_Extensions[PC_CurrentDirectory], exSize );
            EXPECT_EQ( strcmp( ptr, test.storedCwd ), 0 );
            dataSize += exSize;
        }

        // check event length
        EXPECT_EQ( process->m_EventSize, dataSize );

        kill( child, 9 );
        unlink( exepath );
        rmdir( test.cwd );
        rmdir( test.exepath );
        if (cmdline != NULL) {
            free(cmdline_copy);
            free(cmdline);
        }
        i++;
    }
}

// tests the StrIsNum function
TEST( Process, StrIsNum )
{
    EXPECT_TRUE( StrIsNum((char*)"1") );
    EXPECT_TRUE( StrIsNum((char*)"12345") );
    EXPECT_TRUE( StrIsNum((char*)"0") );
    EXPECT_FALSE( StrIsNum((char*)"") );
    EXPECT_FALSE( StrIsNum((char*)"a") );
    EXPECT_FALSE( StrIsNum((char*)"abc") );
    EXPECT_FALSE( StrIsNum((char*)"a123") );
    EXPECT_FALSE( StrIsNum((char*)"123a") );
    EXPECT_FALSE( StrIsNum((char*)"12a34") );
}

int DwordCmp(const void* a, const void* b)
{
    DWORD c = *(DWORD*)a;
    DWORD d = *(DWORD*)b;

    if (c<d) return -1;
    if (c>d) return 1;
    return 0;
}

// tests the EnumProcesses function
TEST( Process, EnumProcesses )
{
    FILE *fp;
    DWORD actual[128 * 1024];
    DWORD test[128 * 1024];
    DWORD test_used = 0;
    DWORD test_count = 0;
    DWORD half_test_count = 0;
    DWORD count = 0;
    DWORD onlyInTest = 0;
    DWORD onlyInActual = 0;
    DWORD test_index = 0;
    DWORD actual_index = 0;

    usleep(10000);

    fp = popen("ps -ef | grep -v \"ps -ef\\|tail -n +2\\|print \\$2\\|sort -un\\|grep -v\" | tail -n +2 | awk {'print $2'} | sort -un", "r");
    ASSERT_TRUE( fp != NULL );
    while (fscanf(fp, "%d", &actual[count]) == 1) {
        count++;
    }
    pclose(fp);

    ASSERT_TRUE( EnumProcesses( test, 128 * 1024 * sizeof(DWORD), &test_used ) );
    test_count = test_used / sizeof(DWORD);
    // assume more than 30 processes as almost all systems will have at least 30 kernel-based processes
    EXPECT_TRUE( test_count > 30 );
    EXPECT_TRUE( count > 30 );

    // sort the process list
    qsort(test, test_count, sizeof(DWORD), DwordCmp);

    while (test_index < test_count && actual_index < count) {
        if (test[test_index] < actual[actual_index]) {
            onlyInTest++;
            test_index++;
        } else if (test[test_index] > actual[actual_index]) {
            onlyInActual++;
            actual_index++;
        } else {
            test_index++;
            actual_index++;
        }
    }

    onlyInTest += test_count - test_index;
    onlyInActual += count - actual_index;

    // assume process lists are within 3 processes of each other
    EXPECT_TRUE( onlyInTest < 3 );
    EXPECT_TRUE( onlyInActual < 5 );

    // test where memory is too small for process list
    half_test_count = test_count / 2;
    ASSERT_TRUE( EnumProcesses( test, half_test_count * sizeof(DWORD), &test_used ) );
    test_count = test_used / sizeof(DWORD);
    ASSERT_EQ( half_test_count, test_count );
}

// tests the GUID function
TEST( Process, StringFromGUID2 )
{
    CHAR buf[39];
    const GUID g = { 0x01234567, 0x89ab, 0xcdef, { 0x12, 0x34, 0x56, 0x78, 0xfe, 0xdc, 0xba, 0x90 } };

    EXPECT_EQ( StringFromGUID2( g, buf, sizeof(buf) ), sizeof(buf) );
    EXPECT_EQ( strcmp( buf, "{01234567-89ab-cdef-1234-5678fedcba90}" ), 0 );
    // check error condition for buffer too small
    EXPECT_EQ( StringFromGUID2( g, buf, 38 ), 0 );
}

// tests the login time function
TEST( Process, GetLogonTime )
{
    FILE *fp;
    char *whoEntry = NULL;
    size_t whoLen = 0;
    char *username = NULL;
    char *tty = NULL;
    unsigned int ttyNum = 0;
    char *dateStr = NULL;
    char *ptr = NULL;
    struct passwd *pwd;
    LUID luid;
    LARGE_INTEGER timestamp;
    char logonTimeStr[64];
    struct tm logonTime;
    time_t logonSeconds;
    unsigned int count = 0;

    fp = popen("who", "r");
    ASSERT_NE( fp, nullptr );
    while (getline( &whoEntry, &whoLen, fp ) != -1) {
        printf("%s", whoEntry);
        username = whoEntry;

        // terminate username and skip white space
        ptr = strchr( username, ' ' );
        ASSERT_NE( ptr, nullptr);
        *ptr++ = 0;
        while (*ptr == ' ') {
            ptr++;
        }

        // parse tty
        tty = ptr;
        ptr = strchr( tty, '/' );

        // No tty, skip.
        if (ptr == nullptr) {
                continue;
        }
        ptr++;
        ttyNum = atoi( ptr );

        // skip white space
        ptr = strchr( ptr, ' ' );
        ASSERT_NE( ptr, nullptr );
        ptr++;

        while (*ptr == ' ') {
            ptr++;
        }
        dateStr = ptr;
        // find end of date string and terminate
        ptr = strchr( ptr, ' ' );
        ASSERT_NE( ptr, nullptr );
        ptr = strchr( ptr+1, ' ' );
        ASSERT_NE( ptr, nullptr );
        *ptr = 0;

        pwd = getpwnam( username );
        ASSERT_NE( pwd, nullptr );

        // construct LUID
        luid.LowPart = pwd->pw_uid;
        luid.HighPart = ttyNum;

        timestamp = GetLogonTime( &luid );
        EXPECT_NE( timestamp.QuadPart, 0 );

        logonSeconds = (uint64_t)timestamp.QuadPart / (1000 * 1000 * 10);
        //EXPECT_TRUE( gmtime_r( &logonSeconds, &logonTime ) != NULL );
        EXPECT_NE( localtime_r( &logonSeconds, &logonTime ), nullptr );
        EXPECT_GT( strftime( logonTimeStr, 64, "%Y-%m-%d %H:%M", &logonTime ), 0 );
        EXPECT_STREQ( dateStr, logonTimeStr );
        count++;
    }
    printf("Checked %d logon times\n", count);
}

// tests the creation of the syslog string
TEST( Process, FormatSyslogString )
{
    EVENT_DATA_DESCRIPTOR fields[3];
    char event[4096];
    SYSMON_EVENT_TYPE_FMT EventType;
    CONST TCHAR eventName[] = "TestEvent";
    int eventIdFd = 0;

    umask(022);
    eventIdFd = open("/tmp/sysmonUnitTest.FormatSyslogString", O_RDWR | O_CREAT, S_IRWXU);
    ASSERT_TRUE(eventIdFd > 0);
    ASSERT_EQ(fallocate(eventIdFd, 0, 0, sizeof(uint64_t)), 0);
    eventIdAddr = (uint64_t *)mmap(NULL, sizeof(uint64_t), PROT_READ | PROT_WRITE, MAP_SHARED, eventIdFd, 0);
    ASSERT_TRUE(eventIdAddr != NULL && eventIdAddr != MAP_FAILED);
    *eventIdAddr = 1337;
    EventType.EventName = (PTCHAR)eventName;
    EventType.EventId = 1;
    EventType.EventDescriptor = &SYSMONEVENT_CREATE_PROCESS_EVENT;
    EventType.FieldNames = SYSMONEVENT_CREATE_PROCESS_FieldNames;
    fields[0].Ptr = (ULONGLONG)"aardvark";
    fields[1].Ptr = (ULONGLONG)"banana";
    fields[2].Ptr = (ULONGLONG)"cat";

    FormatSyslogString( event, 4096, &EventType, fields, 3 );
    char event1[] = "<Event><System><Provider Name=\"Linux-Sysmon\" Guid=\"{ff032593-a8d3-4f13-b0d6-01fc615a0f97}\"/><EventID>1</EventID><Version>5</Version><Level>4</Level><Task>1</Task><Opcode>0</Opcode><Keywords>0x8000000000000000</Keywords><TimeCreated SystemTime=\"0000-00-00T00:00:00";
    char hostname[HOST_NAME_MAX + 1];
    EXPECT_EQ(gethostname(hostname, HOST_NAME_MAX + 1), 0);
    char event1b[512];
    snprintf(event1b, 512, "Z\"/><EventRecordID>1337</EventRecordID><Correlation/><Execution ProcessID=\"%d\" ThreadID=\"%d\"/><Channel>Linux-Sysmon/Operational</Channel><Computer>%s</Computer><Security UserId=\"%d\"/></System><EventData><Data Name=\"RuleName\">aardvark</Data><Data Name=\"UtcTime\">banana</Data><Data Name=\"ProcessGuid\">cat</Data></EventData></Event>", getpid(), GetTid(), hostname, getuid());
    time_t curSeconds = time(NULL);
    struct tm curTime;
    gmtime_r(&curSeconds, &curTime);
    strftime(event1 + 244, 20, "%FT%T", &curTime);
    EXPECT_EQ( strncmp( event, event1, 263 ), 0 );
    EXPECT_EQ( strcmp( event + 273, event1b ), 0 );

    FormatSyslogString( event, 4096, &EventType, fields, 2 );
    char event2[512];
    snprintf(event2, 512, "<EventRecordID>1338</EventRecordID><Correlation/><Execution ProcessID=\"%d\" ThreadID=\"%d\"/><Channel>Linux-Sysmon/Operational</Channel><Computer>%s</Computer><Security UserId=\"%d\"/></System><EventData><Data Name=\"RuleName\">aardvark</Data><Data Name=\"UtcTime\">banana</Data></EventData></Event>", getpid(), GetTid(), hostname, getuid());
    EXPECT_EQ( strcmp( event + 277, event2 ), 0 );

    FormatSyslogString( event, 44, &EventType, fields, 3 );
    EXPECT_EQ( strcmp( event, "<Event><System><Provider Name=\"Linux-Sysmon" ), 0 );

    if (eventIdAddr != NULL && eventIdAddr != MAP_FAILED) {
        munmap(eventIdAddr, sizeof(uint64_t));
    }
    if (eventIdFd > 0) {
        close(eventIdFd);
    }
    unlink("/tmp/sysmonUnitTest.FormatSyslogString");
}

char FakeSyslog[4096];
extern "C" {
VOID syslogHelper( int priority, const char* fmt, const char *msg )
{
    sprintf(FakeSyslog, fmt, msg);
}
}


TEST( Events, DispatchEvent )
{
    char*                   ptr = NULL;
    PSYSMON_EVENT_HEADER    event = NULL;
    PSYSMON_PROCESS_CREATE  pc = NULL;
    tstring ruleTempFile;
    PVOID Rules;
    ULONG RulesSize;
    ULONG eventSize = 0;
    size_t len = 0;
    int eventIdFd = 0;
    const char* im = "/foo/bar/image";

	*FakeSyslog = 0x00;

    umask(022);
    eventIdFd = open("/tmp/sysmonUnitTest.DispatchEvent", O_RDWR | O_CREAT, S_IRWXU);
    ASSERT_TRUE(eventIdFd > 0);
    ASSERT_EQ(fallocate(eventIdFd, 0, 0, sizeof(uint64_t)), 0);
    eventIdAddr = (uint64_t *)mmap(NULL, sizeof(uint64_t), PROT_READ | PROT_WRITE, MAP_SHARED, eventIdFd, 0);
    ASSERT_TRUE(eventIdAddr != NULL && eventIdAddr != MAP_FAILED);
    *eventIdAddr = 5;

    SysmonRule s = SysmonRule( testDefaultVersion,
            RuleEntry( "EventFiltering",
                RuleEntry( "ProcessCreate", "onmatch", "exclude", RuleEntry::Empty ) ) );

    ASSERT_EQ(WriteTempStringFile(s.Output(), ruleTempFile), TRUE);
    ASSERT_EQ(ApplyConfigurationFile(const_cast<PTCHAR>(ruleTempFile.c_str()), &Rules, &RulesSize, TRUE), TRUE);

    event = (PSYSMON_EVENT_HEADER)malloc(65536);
    if(event==NULL)
    {
        ASSERT_TRUE(false);
    }
    pc = &event->m_EventBody.m_ProcessCreateEvent;

    event->m_EventType = ProcessCreate;
    event->m_FieldFiltered = 0;
    event->m_PreFiltered = 0;
    event->m_SequenceNumber = 12345;
    event->m_SessionId = 67890;

    pc->m_ProcessKey = 0xdeadbeef12345678;
    pc->m_ProcessId = 54321;
    pc->m_ParentProcessId = 98765;
    pc->m_SessionId = 333;
    pc->m_AuditUserId = 1;
    GetSystemTimeAsLargeInteger( &pc->m_CreateTime );
    pc->m_AuthenticationId.HighPart = 678;
    pc->m_AuthenticationId.LowPart = 345;
    pc->m_IsAppContainer = 0;
    pc->m_HashType = 0;
    pc->m_ParentProcessObject = 0;
    pc->m_ProcessObject = 0;

    memset( pc->m_Extensions, 0, sizeof(pc->m_Extensions) );

    eventSize = sizeof(SYSMON_EVENT_HEADER);

    ptr = (char*)(pc + 1);
    len = strlen(im) + 1;
    memcpy(ptr, im, len);
    len = strlen(ptr) + 1;
    pc->m_Extensions[PC_ImagePath] = len;
    ptr += len;
    eventSize += len;

    strcpy(ptr, "image arg1 arg2");
    len = strlen(ptr) + 1;
    pc->m_Extensions[PC_CommandLine] = len;
    ptr += len;
    eventSize += len;

    strcpy(ptr, "/bar/foo");
    len = strlen(ptr) + 1;
    pc->m_Extensions[PC_CurrentDirectory] = len;
    eventSize += len;

    event->m_EventSize = eventSize;

    DispatchEvent(event);
    printf("syslog output = '%s'\n", FakeSyslog);

    PSYSMON_EVENT_HEADER process = (PSYSMON_EVENT_HEADER)malloc(65536);
    char *cmdline[4];
    cmdline[0] = (char*)"msleep";
    cmdline[1] = (char*)"abc";
    cmdline[2] = (char*)"5";
    cmdline[3] = NULL;

    pid_t pid = fork();

    // We are not using the GTEST ASSERT_* here as the static analysis seems to think that
    // its possible to have a memory leak. We explicitly check the value and free memory
    // that the analyzer is complaining about and then ASSERT.
    if(pid < 0)
    {
        free(process);
        process = NULL;
        ASSERT_TRUE(false);
    }

    if (pid == 0) {
        execve("./mysleep", cmdline, NULL);
    }

    usleep(10000);

    ASSERT_TRUE(GetProcess(process, 65536, pid));

    DispatchEvent(process);
    printf("syslog output = '%s'\n", FakeSyslog);

    if (eventIdAddr != NULL && eventIdAddr != MAP_FAILED) {
        munmap(eventIdAddr, sizeof(uint64_t));
    }
    if (eventIdFd > 0) {
        close(eventIdFd);
    }
    unlink(ruleTempFile.c_str());
    unlink("/tmp/sysmonUnitTest.DispatchEvent");

    free(event);
}


// TranslateNULLSid checks that TranslateSid correctly handles a NULL SID.
TEST( Events, TranslateNULLSid )
{
    CHAR buffer[20];
    memset(buffer, 0x41, sizeof(buffer));
    TranslateSid(NULL, buffer, sizeof(buffer));
    ASSERT_EQ(buffer[0], 0);
}
