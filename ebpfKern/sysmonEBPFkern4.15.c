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
// sysmonEBPFkern4.15.c
//
// eBPF programs for kernel v4.15.
//
//====================================================================

#define SUB4096 1
#define NOLOOPS 1

#define FILEPATH_NUMDIRS 5

#include "sysmonGenericEntry_tp.c"
#include "sysmonProcCreate_tp.c"
#include "sysmonFileCreate_tp.c"
#include "sysmonFileOpen_tp.c"
#include "sysmonFileDelete_tp.c"
#include "sysmonFileDeleteAt_tp.c"
#include "sysmonFileDeleteAtCwd_tp.c"
#include "sysmonProcTerminated.c"
#include "sysmonTCPaccept_tp.c"
#include "sysmonTCPconnection_4_15.c"
#include "sysmonProcAccessed_tp.c"
#include "sysmonUDPsend.c"
#include "sysmonUDPrecv_tp.c"
#include "sysmonCloseFD_tp.c"
#include "sysmonBPFLoad_tp.c"

char _license[] SEC("license") = "GPL";
