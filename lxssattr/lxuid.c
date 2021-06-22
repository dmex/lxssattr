#include "main.h"

void PrintLxuid(PFILE_FULL_EA_INFORMATION buffer)
{
    ULONG attrValue = 0;
    RtlCopyMemory(&attrValue, buffer->EaName + (buffer->EaNameLength + 1), sizeof(ULONG32));

    _tprintf(_T("%S:                    Uid: (%lu / %s)\n"),
        NTFS_EX_ATTR_LXUID,
        attrValue,
        GetUserNameFromUid(attrValue)
    );
}

void PrintLxgid(PFILE_FULL_EA_INFORMATION buffer)
{
    ULONG attrValue = 0;
    RtlCopyMemory(&attrValue, buffer->EaName + (buffer->EaNameLength + 1), sizeof(ULONG32));

    _tprintf(_T("%S:                    Gid: (%lu / %s)\n"),
        NTFS_EX_ATTR_LXGID,
        attrValue,
        GetGroupNameFromGid(attrValue)
    );
}

void PrintLxmod(PFILE_FULL_EA_INFORMATION buffer)
{
    ULONG attrValue = 0;
    RtlCopyMemory(&attrValue, buffer->EaName + (buffer->EaNameLength + 1), sizeof(ULONG32));

    _tprintf(_T("%S:                    Mode: %o (octal)\n"), NTFS_EX_ATTR_LXMOD, attrValue);
}