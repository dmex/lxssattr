#pragma once

#define WIN32_LEAN_AND_MEAN
#define _CRT_SECURE_NO_WARNINGS

#define WIN32_NO_STATUS
#include <Windows.h>
#undef WIN32_NO_STATUS

#include <winternl.h>
#include <ntstatus.h>
#include <stdlib.h>
#include <tchar.h>
#include <time.h>

// Include after SDK headers.
#include "phnt.h"
#include "posix.h"

// posix.c 
PSTR lsperms(_In_ INT mode);

// main.c
VOID DumpEaInformaton(
    _In_ PFILE_FULL_EA_INFORMATION Info
    );