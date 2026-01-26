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
// sysmonEBPFkern4.17-5.1.c
//
// eBPF programs for kernel v4.17 to v5.1 inclusive.
//
//====================================================================

#define SUB4096 1
#define NOLOOPS 1

#define FILEPATH_NUMDIRS 5

#include "sysmonGenericEntry_rawtp.c"
#include "sysmonProcCreate_rawtp.c"
#include "sysmonFileCreate_rawtp.c"
#include "sysmonFileOpen_rawtp.c"
#include "sysmonFileDelete_rawtp.c"
#include "sysmonFileDeleteAt_rawtp.c"
#include "sysmonFileDeleteAtCwd_rawtp.c"
#include "sysmonProcTerminated.c"
#include "sysmonTCPaccept_rawtp.c"
#include "sysmonTCPconnection_4_16_5_5.c"
#include "sysmonProcAccessed_rawtp.c"
#include "sysmonUDPsend.c"
#include "sysmonUDPrecv_rawtp.c"
#include "sysmonCloseFD_rawtp.c"
#include "sysmonBPFLoad_rawtp.c"

char _license[] SEC("license") = "GPL";
