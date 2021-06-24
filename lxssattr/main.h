#pragma once

#define WIN32_LEAN_AND_MEAN
#define _CRT_SECURE_NO_WARNINGS

#define WIN32_NO_STATUS
#include <Windows.h>
#undef WIN32_NO_STATUS

#include <winternl.h>
#include <ntstatus.h>
#include <malloc.h>
#include <stdlib.h>
#include <stdio.h>
#include <tchar.h>
#include <time.h>
#include <winioctl.h>

// Include after SDK headers.
#include "phnt.h"
#include "posix.h"
#include "list.h"
#include "lxattrb.h"
#include "lxuid.h"

// posix.c 
char filetypeletter(int mode);
PSTR lsperms(_In_ INT mode);

// main.c
VOID DumpEaInformaton(
    _In_ PFILE_FULL_EA_INFORMATION Info
    );

// utils.c

typedef struct _USER_ENTRY
{
    LIST_ENTRY ListEntry;

    PTSTR Name;
    ULONG Uid;
    ULONG Gid;
} USER_ENTRY, *PUSER_ENTRY;

typedef struct _GROUP_ENTRY
{
    LIST_ENTRY ListEntry;

    PTSTR Name;
    ULONG Gid;
} GROUP_ENTRY, *PGROUP_ENTRY;

PTSTR UnixStatTime(
    _In_ ULONG64 Time, 
    _In_ ULONG NanoSeconds
    );

VOID LxssLoadUsersFile(
    VOID
    );

VOID LxssLoadGroupsFile(
    VOID
    );

PTSTR GetUserNameFromUid(
    _In_ ULONG Uid
    );

PTSTR GetGroupNameFromGid(
    _In_ ULONG Gid
    );