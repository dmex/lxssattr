#include "main.h"

void PrintLxuid(PFILE_FULL_EA_INFORMATION buffer)
{
    ULONG st_uid = 0;
    RtlCopyMemory(&st_uid, buffer->EaName + (buffer->EaNameLength + 1), sizeof(ULONG));

    _tprintf(_T("%S:                    Uid: (%lu / %s)\n"),
        NTFS_EX_ATTR_LXUID, st_uid, GetUserNameFromUid(st_uid)
    );
}

void PrintLxgid(PFILE_FULL_EA_INFORMATION buffer)
{
    ULONG st_gid = 0;
    RtlCopyMemory(&st_gid, buffer->EaName + (buffer->EaNameLength + 1), sizeof(ULONG));

    _tprintf(_T("%S:                    Gid: (%lu / %s)\n"),
        NTFS_EX_ATTR_LXGID, st_gid, GetGroupNameFromGid(st_gid)
    );
}

void PrintLxmod(PFILE_FULL_EA_INFORMATION buffer)
{
    ULONG st_mode = 0;
    RtlCopyMemory(&st_mode, buffer->EaName + (buffer->EaNameLength + 1), sizeof(ULONG));

    _tprintf(_T("%S:                    Mode: %o (octal) Access: (0%o) %hs\n"),
        NTFS_EX_ATTR_LXMOD, st_mode, st_mode & (S_IRWXU | S_IRWXG | S_IRWXO), lsperms(st_mode)
    );
}

void PrintLxdev(PFILE_FULL_EA_INFORMATION buffer)
{
    ULONG type_major = 0;
    RtlCopyMemory(&type_major, buffer->EaName + (buffer->EaNameLength + 1), sizeof(ULONG));

    ULONG type_minor = 0;
    RtlCopyMemory(&type_minor, buffer->EaName + (buffer->EaNameLength + 1) + sizeof(ULONG), sizeof(ULONG));

    _tprintf(_T("%S:                    Device type: %#lx, %#lx\n"),
        NTFS_EX_ATTR_LXDEV, type_major, type_minor
    );
}