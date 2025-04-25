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
// vmlinux_kern_diffs.h
//
// Contains type definitions that are kernel version dependent.
// The type definitions are usually duplicates (although with only
// the fields that are relevant). CO-RE has a special naming convention
// to properly handle this. See "Handling incompatible field and type changes"
// in:
//
// https://nakryiko.com/posts/bpf-core-reference-guide/#defining-own-co-re-relocatable-type-definitions
//
//====================================================================

#ifndef __VMLINUX_KERN_DIFFS_H__
#define __VMLINUX_KERN_DIFFS_H__

#include <vmlinux.h>

struct inode___pre_v611 {
    struct timespec64 __i_atime;
    struct timespec64 __i_mtime;
    struct timespec64 __i_ctime;
};

struct inode___pre_v66 {
    struct timespec64 i_atime;
    struct timespec64 i_mtime;
    struct timespec64 i_ctime;
};


#endif /* __VMLINUX_KERN_DIFFS_H__ */
