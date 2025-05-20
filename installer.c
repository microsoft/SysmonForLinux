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
// installer.c
//
// Functions that install Sysmon For Linux
//
//====================================================================

#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <stdbool.h>
#include <sys/stat.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <signal.h>
#include <libsysinternalsEBPF.h>
#include "sysmonevents.h"
#include "installer.h"
#include "linuxHelpers.h"
#include "sysmon_defs.h"

extern char _binary_sysmonLogView_start[];
extern char _binary_sysmonLogView_end[];
extern char _binary_sysmon_d_start[];
extern char _binary_sysmon_d_end[];
extern char _binary_sysmon_service_start[];
extern char _binary_sysmon_service_end[];
extern char _binary_sysmonEBPFkern4_15_o_start[];
extern char _binary_sysmonEBPFkern4_15_o_end[];
extern char _binary_sysmonEBPFkern4_16_o_start[];
extern char _binary_sysmonEBPFkern4_16_o_end[];
extern char _binary_sysmonEBPFkern4_17_5_1_o_start[];
extern char _binary_sysmonEBPFkern4_17_5_1_o_end[];
extern char _binary_sysmonEBPFkern5_2_o_start[];
extern char _binary_sysmonEBPFkern5_2_o_end[];
extern char _binary_sysmonEBPFkern5_3_5_5_o_start[];
extern char _binary_sysmonEBPFkern5_3_5_5_o_end[];
extern char _binary_sysmonEBPFkern5_6__o_start[];
extern char _binary_sysmonEBPFkern5_6__o_end[];
extern char _binary_sysmonEBPFkern4_15_core_o_start[];
extern char _binary_sysmonEBPFkern4_15_core_o_end[];
extern char _binary_sysmonEBPFkern4_16_core_o_start[];
extern char _binary_sysmonEBPFkern4_16_core_o_end[];
extern char _binary_sysmonEBPFkern4_17_5_1_core_o_start[];
extern char _binary_sysmonEBPFkern4_17_5_1_core_o_end[];
extern char _binary_sysmonEBPFkern5_2_core_o_start[];
extern char _binary_sysmonEBPFkern5_2_core_o_end[];
extern char _binary_sysmonEBPFkern5_3_5_5_core_o_start[];
extern char _binary_sysmonEBPFkern5_3_5_5_core_o_end[];
extern char _binary_sysmonEBPFkern5_6__core_o_start[];
extern char _binary_sysmonEBPFkern5_6__core_o_end[];

mode_t dirMode = S_IRWXU;
mode_t fileMode = S_IRUSR | S_IWUSR;
mode_t exeFileMode = S_IRWXU;
mode_t systemdFileMode = S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH;
mode_t serviceFileMode = S_IRWXU | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH;

//--------------------------------------------------------------------
//
// installFiles
//
// Sysmon is linked with embedded versions of a number of key resource
// files.  This function writes those files to the approprate places.
// The purpose is to make Sysmon a standalone installer so that it can
// be copied to another host and installed there with minimal extra
// dependencies.
//
// Also installs a systemd or initd start up scripts and sets it to
// start up by default.
//
// Returns true on success, otherwise false.
//
//--------------------------------------------------------------------
bool installFiles(bool force)
{
    int fd;
    void *addr = NULL;
    struct stat st;
    const char exePath[] = PROC_EXE_PATH;

    umask(0022);

    if (!createDir(SYSMON_INSTALL_DIR, dirMode)) {
        fprintf(stderr, "Cannot create sysmon directory. Make sure you are root or sudo.\n");
        return false;
    }

    fd = open(exePath, O_RDONLY);
    if (fd < 0)
        return false;

    if (fstat(fd, &st) < 0) {
        close(fd);
        return false;
    }

    addr = mmap(NULL, st.st_size, PROT_READ, MAP_SHARED, fd, 0);
    if (addr == MAP_FAILED) {
        close(fd);
        return false;
    }

    if (!dropFile(SYSMON_INSTALL_DIR "/" SYSMON_BINARY,
        addr,
        addr + st.st_size,
        force,
        exeFileMode)) {
        munmap(addr, st.st_size);
        close(fd);
        return false;
    }

    munmap(addr, st.st_size);
    close(fd);

    if (!dropFile(SYSMON_INSTALL_DIR "/" KERN_4_15_OBJ,
        _binary_sysmonEBPFkern4_15_o_start,
        _binary_sysmonEBPFkern4_15_o_end,
        force,
        fileMode))
        return false;

    if (!dropFile(SYSMON_INSTALL_DIR "/" KERN_4_16_OBJ,
        _binary_sysmonEBPFkern4_16_o_start,
        _binary_sysmonEBPFkern4_16_o_end,
        force,
        fileMode))
        return false;

    if (!dropFile(SYSMON_INSTALL_DIR "/" KERN_4_17_5_1_OBJ,
        _binary_sysmonEBPFkern4_17_5_1_o_start,
        _binary_sysmonEBPFkern4_17_5_1_o_end,
        force,
        fileMode))
        return false;

    if (!dropFile(SYSMON_INSTALL_DIR "/" KERN_5_2_OBJ,
        _binary_sysmonEBPFkern5_2_o_start,
        _binary_sysmonEBPFkern5_2_o_end,
        force,
        fileMode))
        return false;

    if (!dropFile(SYSMON_INSTALL_DIR "/" KERN_5_3_5_5_OBJ,
        _binary_sysmonEBPFkern5_3_5_5_o_start,
        _binary_sysmonEBPFkern5_3_5_5_o_end,
        force,
        fileMode))
        return false;

    if (!dropFile(SYSMON_INSTALL_DIR "/" KERN_5_6__OBJ,
        _binary_sysmonEBPFkern5_6__o_start,
        _binary_sysmonEBPFkern5_6__o_end,
        force,
        fileMode))
        return false;

    if (!dropFile(SYSMON_INSTALL_DIR "/" KERN_4_15_CORE_OBJ,
        _binary_sysmonEBPFkern4_15_core_o_start,
        _binary_sysmonEBPFkern4_15_core_o_end,
        force,
        fileMode))
        return false;

    if (!dropFile(SYSMON_INSTALL_DIR "/" KERN_4_16_CORE_OBJ,
        _binary_sysmonEBPFkern4_16_core_o_start,
        _binary_sysmonEBPFkern4_16_core_o_end,
        force,
        fileMode))
        return false;

    if (!dropFile(SYSMON_INSTALL_DIR "/" KERN_4_17_5_1_CORE_OBJ,
        _binary_sysmonEBPFkern4_17_5_1_core_o_start,
        _binary_sysmonEBPFkern4_17_5_1_core_o_end,
        force,
        fileMode))
        return false;

    if (!dropFile(SYSMON_INSTALL_DIR "/" KERN_5_2_CORE_OBJ,
        _binary_sysmonEBPFkern5_2_core_o_start,
        _binary_sysmonEBPFkern5_2_core_o_end,
        force,
        fileMode))
        return false;

    if (!dropFile(SYSMON_INSTALL_DIR "/" KERN_5_3_5_5_CORE_OBJ,
        _binary_sysmonEBPFkern5_3_5_5_core_o_start,
        _binary_sysmonEBPFkern5_3_5_5_core_o_end,
        force,
        fileMode))
        return false;

    if (!dropFile(SYSMON_INSTALL_DIR "/" KERN_5_6__CORE_OBJ,
        _binary_sysmonEBPFkern5_6__core_o_start,
        _binary_sysmonEBPFkern5_6__core_o_end,
        force,
        fileMode))
        return false;

    if (!dropFile(SYSMON_INSTALL_DIR "/" SYSMONLOGVIEW_BINARY,
        _binary_sysmonLogView_start,
        _binary_sysmonLogView_end,
        force,
        exeFileMode))
        return false;

    if (dirExists(SYSTEMD_DIR)) {
        //
        // systemd managed system
        //
        if (!dropFile(SYSTEMD_DIR "/" SYSTEMD_SERVICE,
            _binary_sysmon_service_start,
            _binary_sysmon_service_end,
            force,
            systemdFileMode))
            return false;
        if(system(SYSTEMD_RELOAD_CMD) == -1) {
	        return false;
	    }
        if(system(SYSTEMD_ENABLE_CMD " " SYSTEMD_SERVICE) == -1) {
	        return false;
	    }
    } else if (dirExists(INITD_DIR)) {
        //
        // init.d / rc script managed system
        //
        if (!dropFile(INITD_DIR "/" INITD_SERVICE,
            _binary_sysmon_d_start,
            _binary_sysmon_d_end,
            force,
            serviceFileMode))
        return false;

        //
        // create symbolic links for the different run states
        // Sysmon not running in 0 (shutdown), 1-2 (single-user)
        // and 6 (reboot); but will run in 3-4 (multi-user) and 5 (desktop),
        // aligned with usual Linux conventions.
        //
        setRunState(0, false);
        setRunState(1, false);
        setRunState(2, false);
        setRunState(3, true);
        setRunState(4, true);
        setRunState(5, true);
        setRunState(6, false);
    }
    return true;
}

//--------------------------------------------------------------------
//
// uninstall
//
// Disables the systemd or initd service.
//
//--------------------------------------------------------------------
void uninstall()
{
    if (dirExists(SYSTEMD_DIR)) {
        if (system(SYSTEMD_DISABLE_CMD " " SYSTEMD_SERVICE) == -1) {
            return;
        }
    } else if (dirExists(INITD_DIR)) {
        setRunState(0, false);
        setRunState(1, false);
        setRunState(2, false);
        setRunState(3, false);
        setRunState(4, false);
        setRunState(5, false);
        setRunState(6, false);
    }
}

//--------------------------------------------------------------------
//
// copyConfigFile
//
// Copies the supplied config file to the Sysmon install directory.
//
// Returns true on success, otherwise false.
//
//--------------------------------------------------------------------
bool copyConfigFile(const char *configFile)
{
    if (configFile == NULL) {
        fprintf(stderr, "copyConfigFile invalid params\n");
        return false;
    }

    int fd;
    void *addr = NULL;
    struct stat st;
    bool ret = true;
    char realConfigPath[PATH_MAX];
    char realTargetPath[PATH_MAX];

    if (!fileExists(configFile))
        return false;

    if (realpath(configFile, realConfigPath) == NULL)
        return false;

    snprintf(realTargetPath, sizeof(realTargetPath), "%s", SYSMON_CONFIG_FILE);

    if (strcmp(realConfigPath, realTargetPath) == 0)
        return true;

    fd = open(configFile, O_RDONLY);
    if (fd < 0)
        return false;

    if (fstat(fd, &st) < 0) {
        close(fd);
        return false;
    }

    addr = mmap(NULL, st.st_size, PROT_READ, MAP_SHARED, fd, 0);
    if (addr == MAP_FAILED) {
        close(fd);
        return false;
    }

    if (!dropFile(realTargetPath,
        addr,
        addr + st.st_size,
        true,
        fileMode)) {
        ret = false;
    }

    munmap(addr, st.st_size);
    close(fd);
    return ret;
}

//--------------------------------------------------------------------
//
// createEmptyConfigFile
//
// For situations where Sysmon was configured without a configuration
// file, this function creates an empty one to represent that fact
// (and because the systemd and initd start up scripts expect a config
// file).
//
// Returns true on success, otherwise false.
//
//--------------------------------------------------------------------
bool createEmptyConfigFile()
{
    bool ret = false;
    int fd = 0;
    char empty[] = "<Sysmon schemaversion=\"4.22\">\n<EventFiltering>\n</EventFiltering>\n</Sysmon>\n";

    fd = creat(SYSMON_CONFIG_FILE, fileMode);
    if (fd < 0)
        return false;

    if (write(fd, empty, strlen(empty)) != -1) {
        ret = true;
    }

    close(fd);

    return ret;
}

//--------------------------------------------------------------------
//
// writeArgv
//
// Writes the argc and argv of the commandline to files in the Sysmon
// install directory for later use.
//
// Returns true on success, otherwise false.
//
//--------------------------------------------------------------------
bool writeArgv(int argc, char *argv[])
{
    if (argv == NULL) {
        fprintf(stderr, "writeArgv invalid params\n");
        return false;
    }

    int fd;

    unlink(SYSMON_ARGC_FILE);
    fd = creat(SYSMON_ARGC_FILE, fileMode);
    if (fd < 0)
        return false;

    if (write(fd, &argc, sizeof(argc)) == -1) {
        close(fd);
        return false;
    }

    close(fd);

    unlink(SYSMON_ARGV_FILE);
    fd = creat(SYSMON_ARGV_FILE, fileMode);
    if (fd < 0)
        return false;

    for (int i=0; i<argc; i++) {
        if (write(fd, argv[i], strlen(argv[i]) + 1) == -1) {
            close(fd);
            return false;
        }
    }
    close(fd);

    return true;
}

//--------------------------------------------------------------------
//
// readArgv
//
// Reads the stored argc and argv.  Switches the config file in the
// command line (if it exists) with the path to the one in the Sysmon
// install directory, and returns the one in the command line as
// configFile.
//
// Returns true on success, otherwise false.
//
//--------------------------------------------------------------------
bool readArgv(int *argc, char ***argv, char **configFile)
{
    if (argc == NULL || argv == NULL || configFile == NULL) {
        fprintf(stderr, "readArgv invalid params\n");
        return false;
    }

    int fd;
    struct stat st;
    char *data;
    unsigned int ptrTableSize = 0;
    char *specialConfigFile = NULL;
    bool sawConfigFileSwitch = false;

    *configFile = NULL;

    fd = open(SYSMON_ARGC_FILE, O_RDONLY);
    if (fd < 0)
        return false;

    if (read(fd, argc, sizeof(*argc)) == -1) {
        close(fd);
        return false;
    }

    close(fd);

    ptrTableSize = sizeof(char *) * (*argc+1);

    fd = open(SYSMON_ARGV_FILE, O_RDONLY);
    if (fd < 0)
        return false;

    if (fstat(fd, &st) < 0) {
        close(fd);
        return false;
    }

    // allocate space for the string pointers followed by the strings, plus
    // space for special config file
    *argv = (char **)malloc(ptrTableSize + st.st_size + strlen(SYSMON_CONFIG_FILE) + 1);
    if (*argv == NULL) {
        close(fd);
        return false;
    }

    data = (char *)(*argv) + ptrTableSize;

    // read actual strings
    if (read(fd, data, st.st_size) == -1) {
        close(fd);
        return false;
    }

    close(fd);

    // write special config file to end
    specialConfigFile = data + st.st_size;
    strcpy(specialConfigFile, SYSMON_CONFIG_FILE);

    // make pointers
    for (int i=0; i<*argc; i++) {
        // if previous arg was '-i' or '-c' and this arg doesn't start with '-'
        // then point to the special config file instead and return the actual
        // config file in configFile
        if (sawConfigFileSwitch && data[0] != '-') {
            (*argv)[i] = specialConfigFile;
            *configFile = data;
        } else {
            (*argv)[i] = data;
        }
        data += strlen(data) + 1;

        if (strcasecmp((*argv)[i], "-i") == 0 || strcasecmp((*argv)[i], "-c") == 0) {
            sawConfigFileSwitch = true;
        } else {
            sawConfigFileSwitch = false;
        }
    }
    // add the null pointer to the end
    (*argv)[*argc] = NULL;

    return true;
}

//--------------------------------------------------------------------
//
// GetCommandLine
//
// Obtains the command line from the files in the Sysmon install dir
// and returns a pointer to a newly malloced buffer containing it.
//
// Returns a new pointer on success, otherwise NULL.
//
//--------------------------------------------------------------------
char *GetCommandLine()
{
    static char *cmdline = NULL;
    int argc = 0;
    char **argv = NULL;
    char *configFile = NULL;
    unsigned int i;
    unsigned int totalSize = 0;
    char *ptr = NULL;

    if (!readArgv(&argc, &argv, &configFile)) {
        return cmdline;
    }

    if (argc <= 0) {
        free(argv);
        return cmdline;
    }

    for (i=0; i<argc; i++) {
        totalSize += strlen(argv[i]) + 1;
    }

    if (totalSize == 0) {
        free(argv);
        return cmdline;
    }

    if (cmdline != NULL) {
        free(cmdline);
    }

    cmdline = (char *)malloc(totalSize);
    if (cmdline == NULL) {
        free(argv);
        return NULL;
    }

    ptr = cmdline;
    for (i=0; i<argc; i++) {
        strcpy(ptr, argv[i]);
        ptr += strlen(argv[i]);
        *ptr = ' ';
        ptr++;
    }

    // change last space to a null
    ptr--;
    *ptr = 0x00;

    free(argv);

    return cmdline;
}

//--------------------------------------------------------------------
//
// writeFieldSizes
//
// Writes the FieldSizes argument in the configuration file to a file
// in the Sysmon install directory for later use.
//
// Returns true on success, otherwise false.
//
//--------------------------------------------------------------------
bool writeFieldSizes(char *fieldSizesStr)
{
    bool ret = false;
    unlink(SYSMON_FIELDSIZES_FILE);

    if (fieldSizesStr == NULL) {
        // if string is NULL, just erase the file
        return true;
    }

    int fd;

    fd = creat(SYSMON_FIELDSIZES_FILE, fileMode);
    if (fd < 0)
        return false;

    if (write(fd, fieldSizesStr, strlen(fieldSizesStr) + 1) != -1) {
        ret = true;
    }

    close(fd);

    return ret;
}

//--------------------------------------------------------------------
//
// readFieldSizes
//
// Reads the stored FieldSizes argument.
//
// Returns allocated buffer containing FieldSizes on success, NULL
// otherwise.
//
//--------------------------------------------------------------------
char *readFieldSizes()
{
    int fd;
    struct stat st;
    char *data;

    fd = open(SYSMON_FIELDSIZES_FILE, O_RDONLY);
    if (fd < 0)
        return NULL;

    if (fstat(fd, &st) < 0) {
        close(fd);
        return NULL;
    }

    // allocate space for the string
    data = (char *)malloc(st.st_size);
    if (data == NULL) {
        close(fd);
        return NULL;
    }

    if (read(fd, data, st.st_size) == -1) {
        close(fd);
        free(data);
        return NULL;
    }

    close(fd);

    return data;
}

//--------------------------------------------------------------------
//
// setRunState
//
// Sets the initd runState (0-6) to running/not-running according to
// the running bool.
//
// Returns true on success, otherwise false.
//
//--------------------------------------------------------------------
bool setRunState(unsigned int runState, bool running)
{
    char startLink[PATH_MAX];
    char killLink[PATH_MAX];

    if (runState > 6)
        return false;

    snprintf(startLink, sizeof(startLink), INITD_DIR_FMT "/" INITD_START_ID INITD_SERVICE, runState);
    snprintf(killLink, sizeof(killLink), INITD_DIR_FMT "/" INITD_KILL_ID INITD_SERVICE, runState);
    if (running) {
        unlink(killLink);
        if (symlink(INITD_DIR "/" INITD_SERVICE, startLink) < 0) {
            return false;
        }
    } else {
        unlink(startLink);
        if (symlink(INITD_DIR "/" INITD_SERVICE, killLink) < 0) {
            return false;
        }
    }
    return true;
}

//--------------------------------------------------------------------
//
// stopSysmonService
//
// Stops the systemd or initd Sysmon service.
//
// Returns true on success, otherwise false.
//
//--------------------------------------------------------------------
bool stopSysmonService()
{
    if (fileExists(SYSTEMD_DIR "/" SYSTEMD_SERVICE)) {
        if (system(SYSTEMD_STOP_CMD " " SYSTEMD_SERVICE) == -1) {
            return false;
        }

        return true;
    } else if (fileExists(INITD_DIR "/" INITD_SERVICE)) {
        if (system(INITD_DIR "/" INITD_SERVICE " stop") == -1) {
            return false;
        }

        return true;
    }
    return false;
}

//--------------------------------------------------------------------
//
// startSysmonService
//
// Starts the systemd or initd Sysmon service.  If the running Sysmon
// was already started as a service, it does nothing and returns true.
//
// Returns true on success, otherwise false.
//
//--------------------------------------------------------------------
bool startSysmonService()
{
    if (OPT_SET(Service))
        return true;

    if (fileExists(SYSTEMD_DIR "/" SYSTEMD_SERVICE)) {
        execl("/bin/sh", "sh", "-c", SYSTEMD_START_CMD " " SYSTEMD_SERVICE, NULL);
    } else if (fileExists(INITD_DIR "/" INITD_SERVICE)) {
        execl("/bin/sh", "sh", "-c", INITD_DIR "/" INITD_SERVICE " start", NULL);
    }
    return false;
}

//--------------------------------------------------------------------
//
// sysmonSearch
//
// Searches for other Sysmon processes and optionally kills them if
// the supplied signal is >=0.
//
// For signal < 0 (e.g. search), returns true if Sysmon is found
// running.
// For signal >= 0 (e.g. kill), returns true if at least one Sysmon
// was found running and was sent the signal.
//
//--------------------------------------------------------------------
bool sysmonSearch(int signal)
{
    pid_t                       pid = getpid();
    char                        exe[PATH_MAX];
    char                        path[2 * PATH_MAX]; // artifically long to
                                                    // handle edge-cases
    const char                  *name;
    DIR                         *d;
    struct dirent               *dir;
    int                         path_len;
    bool                        killed = false;

    d = opendir("/proc");
    if (d) {
        while ((dir = readdir(d)) != NULL) {
            if (!StrIsNum(dir->d_name) || pid == atoi(dir->d_name))
                continue;
            snprintf(exe, PATH_MAX, PROC_EXE_PATH_FMT, atoi(dir->d_name));
            path_len = readlink(exe, path, PATH_MAX);
            if (path_len <= 0)
                continue;
            path[path_len] = 0x00;
            name = strrchr(path, '/');
            if (name == NULL)
                continue;
            if (strcmp(name+1, SYSMON_BINARY) != 0 && strcmp(name+1, SYSMON_BINARY " (deleted)") != 0)
                continue;
            if (signal >= 0) {
                kill(atoi(dir->d_name), signal);
                killed = true;
            } else {
                return true;
            }
        }
        closedir(d);
    }

    if (signal >= 0 && killed)
        return true;

    return false;
}

//--------------------------------------------------------------------
//
// killOtherSysmon
//
// Sends a SIGTERM to all other Sysmon processes.  If force is true,
// also sends SIGKILL to any remaining Sysmon processes.
//
//--------------------------------------------------------------------
void killOtherSysmon(bool force)
{
    sysmonSearch(SIGTERM);
    if (force) {
        sysmonSearch(SIGKILL);
    }
}

//--------------------------------------------------------------------
//
// sysmonIsRunning
//
// Checks if Sysmon is running and returns true if at least one is,
// and false otherwise.
//
//--------------------------------------------------------------------
bool sysmonIsRunning()
{
    return sysmonSearch(-1);
}

//--------------------------------------------------------------------
//
// signalConfigChange
//
// Sends a SIGHUP to the running Sysmon process to indicate that it
// should read the new config stored in the install directory.
//
//--------------------------------------------------------------------
void signalConfigChange()
{
    sysmonSearch(SIGHUP);
}


