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
// sysmonEBPFkern5.6-.c
//
// eBPF programs for kernel v5.6 and later.
//
//====================================================================

#define FILEPATH_NUMDIRS 16

#include "sysmonGenericEntry_rawtp.c"
#include "sysmonProcCreate_rawtp.c"
#include "sysmonFileCreate_rawtp.c"
#include "sysmonFileOpen_rawtp.c"
#include "sysmonFileDelete_rawtp.c"
#include "sysmonFileDeleteAt_rawtp.c"
#include "sysmonFileDeleteAtCwd_rawtp.c"
#include "sysmonProcTerminated.c"
#include "sysmonTCPaccept_rawtp.c"
#include "sysmonTCPconnection_5_6_.c"
#include "sysmonProcAccessed_rawtp.c"
#include "sysmonUDPsend.c"
#include "sysmonUDPrecv_rawtp.c"
#include "sysmonCloseFD_rawtp.c"
#include "sysmonBPFLoad_rawtp.c"

char _license[] SEC("license") = "GPL";
