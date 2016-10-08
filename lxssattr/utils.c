// This entire file should be rewritten, but it's simple and it works.

#include "main.h"

static LIST_ENTRY UsersListHead = { &UsersListHead, &UsersListHead };
static LIST_ENTRY GroupsListHead = { &GroupsListHead, &GroupsListHead };

PTSTR UnixStatTime(
    _In_ ULONG64 Time, 
    _In_ ULONG NanoSeconds
    )
{
    struct tm localTime;
    static TCHAR timeFormat[0x50] = _T("");
    static TCHAR timeBuffer[0x50] = _T("");

    RtlZeroMemory(timeBuffer, sizeof(timeBuffer));

    if (!localtime_s(&localTime, &Time))
    {
        // NOTE: This is how the Linux stat command formats the file times.

        _tcsftime(
            timeFormat, 
            ARRAYSIZE(timeFormat), 
            L"%Y-%m-%d %H:%M:%S.%%09lu %z", 
            &localTime
            );

        _sntprintf(
            timeBuffer, 
            ARRAYSIZE(timeBuffer), 
            timeFormat, 
            NanoSeconds
            );
    }

    return timeBuffer;
}

VOID LxssLoadUsersFile(
    VOID
    )
{
    FILE* fileStream;
    ULONG filePathLength;
    PTSTR filePathBuffer;

    filePathLength = ExpandEnvironmentStrings(
        _T("%LOCALAPPDATA%\\lxss\\rootfs\\etc\\passwd"),
        NULL, 
        0
        );

    filePathBuffer = HeapAlloc(
        GetProcessHeap(), 
        HEAP_ZERO_MEMORY, 
        filePathLength * sizeof(TCHAR) + 1
        );

    ExpandEnvironmentStrings(
        _T("%LOCALAPPDATA%\\lxss\\rootfs\\etc\\passwd"),
        filePathBuffer, 
        filePathLength
        );

    if (!_tfopen_s(&fileStream, filePathBuffer, _T("r")))
    {
        TCHAR buffer[0x1000] = _T("");

        while (_fgetts(buffer, sizeof(buffer), fileStream))
        {
            PUSER_ENTRY entry;

            entry = calloc(1, sizeof(USER_ENTRY));
            entry->Name = _tcsdup(_tcstok(buffer, _T(":")));
            _tcstok(NULL, _T(":"));
            entry->Uid = _tcstoul(_tcstok(NULL, _T(":")), NULL, 10);
            entry->Gid = _tcstoul(_tcstok(NULL, _T(":")), NULL, 10);

            InsertTailList(&UsersListHead, &entry->ListEntry);
        }

        fclose(fileStream);
    }

    HeapFree(GetProcessHeap(), 0, filePathBuffer);
}

VOID LxssLoadGroupsFile(
    VOID
    )
{
    FILE* fileStream;
    ULONG filePathLength;
    PTSTR filePathBuffer;

    filePathLength = ExpandEnvironmentStrings(
        _T("%LOCALAPPDATA%\\lxss\\rootfs\\etc\\group"), 
        NULL, 
        0
        );

    filePathBuffer = HeapAlloc(
        GetProcessHeap(), 
        HEAP_ZERO_MEMORY, 
        filePathLength * sizeof(TCHAR) + 1
        );

    ExpandEnvironmentStrings(
        _T("%LOCALAPPDATA%\\lxss\\rootfs\\etc\\group"), 
        filePathBuffer, 
        filePathLength
        );

    if (!_tfopen_s(&fileStream, filePathBuffer, _T("r")))
    {
        TCHAR buffer[0x1000] = _T("");

        while (_fgetts(buffer, sizeof(buffer), fileStream))
        {
            PGROUP_ENTRY entry;

            entry = calloc(1, sizeof(USER_ENTRY));
            entry->Name = _tcsdup(_tcstok(buffer, _T(":")));
            _tcstok(NULL, _T(":"));
            entry->Gid = _tcstoul(_tcstok(NULL, _T(":")), NULL, 10);

            InsertTailList(&GroupsListHead, &entry->ListEntry);
        }

        fclose(fileStream);
    }

    HeapFree(GetProcessHeap(), 0, filePathBuffer);
}

PTSTR GetUserNameFromUid(
    _In_ ULONG Uid
    )
{
    for (PLIST_ENTRY i = UsersListHead.Flink; i != &UsersListHead; i = i->Flink)
    {
        PUSER_ENTRY entry = CONTAINING_RECORD(i, USER_ENTRY, ListEntry);

        if (entry->Uid == Uid)
        {
            return entry->Name;
        }
    }

    return _T("");
}

PTSTR GetGroupNameFromGid(
    _In_ ULONG Gid
    )
{
    for (PLIST_ENTRY i = GroupsListHead.Flink; i != &GroupsListHead; i = i->Flink)
    {
        PGROUP_ENTRY entry = CONTAINING_RECORD(i, GROUP_ENTRY, ListEntry);

        if (entry->Gid == Gid)
        {
            return entry->Name;
        }
    }

    return _T("");
}