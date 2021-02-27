#include "main.h"

typedef struct _LXSS_FILE_EXTENDED_ATTRIBUTES_V1
{
    USHORT Flags;
    USHORT Version;

    ULONG st_mode;       // Mode bit mask constants: https://msdn.microsoft.com/en-us/library/3kyc8381.aspx
    ULONG st_uid;        // Numeric identifier of user who owns file (Linux-specific).
    ULONG st_gid;        // Numeric identifier of group that owns the file (Linux-specific)
    ULONG st_rdev;       // Drive number of the disk containing the file.
    ULONG st_atime_nsec; // Time of last access of file (nano-seconds).
    ULONG st_mtime_nsec; // Time of last modification of file (nano-seconds).
    ULONG st_ctime_nsec; // Time of creation of file (nano-seconds).
    ULONG64 st_atime;    // Time of last access of file.
    ULONG64 st_mtime;    // Time of last modification of file.
    ULONG64 st_ctime;    // Time of creation of file.
} LXSS_FILE_EXTENDED_ATTRIBUTES_V1, *PLXSS_FILE_EXTENDED_ATTRIBUTES_V1;

typedef struct _LXSS_FILE_INFO
{
    IO_STATUS_BLOCK isb;
    OBJECT_ATTRIBUTES oa;
    UNICODE_STRING fileName;
    HANDLE fileHandle;
    FILE_EA_INFORMATION fileEaInfo;
    PFILE_FULL_EA_INFORMATION buffer;
    ULONG bufferLength;
} LXSS_FILE_INFO;

LXSS_FILE_INFO open_lxss_file_info(PWSTR filename)
{
    NTSTATUS status;

    LXSS_FILE_INFO info;
    info.fileName.Length = 0;
    info.fileHandle = NULL;
    info.fileEaInfo.EaSize = 0;
    info.buffer = NULL;
    info.bufferLength = 0;

    if (!NT_SUCCESS(status = RtlDosPathNameToNtPathName_U_WithStatus(
        filename,
        &info.fileName,
        NULL,
        NULL
    )))
    {
        _tprintf(_T("[ERROR] RtlDosPathNameToNtPathName: 0x%x\n"), status);
        goto CleanupExit;
    }

    InitializeObjectAttributes(
        &info.oa,
        &info.fileName,
        OBJ_CASE_INSENSITIVE,
        NULL,
        NULL
    );

    if (!NT_SUCCESS(status = NtOpenFile(
        &info.fileHandle,
        FILE_GENERIC_READ, // includes the required FILE_READ_EA access_mask!
        &info.oa,
        &info.isb,
        FILE_SHARE_READ,
        FILE_SYNCHRONOUS_IO_NONALERT
    )))
    {
        _tprintf(_T("[ERROR] NtOpenFile: 0x%x\n"), status);
        goto CleanupExit;
    }

    //if ((fileHandle = CreateFile(
    //    __targv[1],
    //    FILE_GENERIC_READ, // includes the required FILE_READ_EA access_mask!
    //    FILE_SHARE_READ,
    //    NULL,
    //    OPEN_EXISTING,
    //    0,
    //    NULL
    //    )) == INVALID_HANDLE_VALUE)
    //{
    //    _tprintf(_T("[ERROR] CreateFile: 0x%x\n"), GetLastError());
    //    __leave;
    //}

    // Query the Extended Attribute length
    if (!NT_SUCCESS(status = NtQueryInformationFile(
        info.fileHandle,
        &info.isb,
        &info.fileEaInfo,
        sizeof(FILE_EA_INFORMATION),
        FileEaInformation
    )))
    {
        _tprintf(_T("[ERROR] NtQueryInformationFile: 0x%x\n"), status);
        goto CleanupExit;
    }

    // Allocate memory for the Extended Attribute
    info.bufferLength = info.fileEaInfo.EaSize;
    info.buffer = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, info.bufferLength + 1);

    // Query the Extended Attribute structure.
    if (!NT_SUCCESS(status = NtQueryEaFile(
        info.fileHandle,
        &info.isb,
        info.buffer,
        info.bufferLength,
        TRUE, // return only the first entry that is found
        NULL,
        0,
        NULL,
        FALSE
    )))
    {
        //if (status == STATUS_NO_MORE_EAS)
        //if (status == STATUS_NO_EAS_ON_FILE)
        _tprintf(_T("[ERROR] NtQueryEaFile: 0x%x\n"), status);
        goto CleanupExit;
    }

CleanupExit:
    return info;
}

void close_lxss_file_info(LXSS_FILE_INFO *info)
{
    if (info->fileHandle)
        NtClose(info->fileHandle);

    if (info->fileName.Buffer)
        RtlFreeHeap(GetProcessHeap(), 0, info->fileName.Buffer);

    if (info->buffer)
        HeapFree(GetProcessHeap(), 0, info->buffer);
}

void __cdecl _tmain()
{
    SetConsoleTitle(_T("lxssattr v1.3 by dmex and viruscamp - LXSS extended file attributes viewer and copier"));

    if (__argc != 2 && __argc != 3)
    {
        _tprintf(_T("lxssattr FILENAME\n"));
        _tprintf(_T("\tto show LXATTRB\n"));
        _tprintf(_T("lxssattr SOURCE_FILENAME TARGET_FILENAME\n"));
        _tprintf(_T("\tto copy LXATTRB from SOURCE_FILENAME to TARGET_FILENAME\n"));
        return;
    }

    LxssLoadUsersFile();
    LxssLoadGroupsFile();

    _tprintf(_T("Querying: %s\n\n"), __targv[1]);
    LXSS_FILE_INFO srcinfo = open_lxss_file_info(__targv[1]);
    LXSS_FILE_INFO targetinfo;
    targetinfo.fileName.Length = 0;
    targetinfo.fileHandle = NULL;
    targetinfo.fileEaInfo.EaSize = 0;
    targetinfo.buffer = NULL;
    targetinfo.bufferLength = 0;

    if (_stricmp("LXATTRB", srcinfo.buffer->EaName))
    {
        _tprintf(_T("[ERROR] LXATTRB not found.\n"));
        goto CleanupExit;
    }
    else
    {
        LXSS_FILE_EXTENDED_ATTRIBUTES_V1 extendedAttr;

        // Make temporary copy of the structure
        RtlZeroMemory(&extendedAttr, sizeof(LXSS_FILE_EXTENDED_ATTRIBUTES_V1));
        RtlCopyMemory(
            &extendedAttr,
            srcinfo.buffer->EaName + (srcinfo.buffer->EaNameLength + 1),
            sizeof(LXSS_FILE_EXTENDED_ATTRIBUTES_V1)
            );

        //_tprintf(_T("LXSS Attributes:\n"));
        _tprintf(_T("Flags:                     %hu\n"), extendedAttr.Flags);
        _tprintf(_T("Version:                   %hu\n"), extendedAttr.Version);
        _tprintf(_T("Mode:                      %o (octal)\n"), extendedAttr.st_mode);
        _tprintf(_T("Ownership:                 Uid: (%lu / %s), Gid: (%lu / %s)\n"),
            extendedAttr.st_uid,
            GetUserNameFromUid(extendedAttr.st_uid),
            extendedAttr.st_gid,
            GetGroupNameFromGid(extendedAttr.st_gid)
            );
        _tprintf(_T("Access:                    (0%o) %hs\n"),
            extendedAttr.st_mode & (S_IRWXU | S_IRWXG | S_IRWXO),
            lsperms(extendedAttr.st_mode)
            );
        _tprintf(_T("Last status change:        %s\n"), UnixStatTime(extendedAttr.st_ctime, extendedAttr.st_ctime_nsec));
        _tprintf(_T("Last file access:          %s\n"), UnixStatTime(extendedAttr.st_atime, extendedAttr.st_atime_nsec));
        _tprintf(_T("Last file modification:    %s\n"), UnixStatTime(extendedAttr.st_mtime, extendedAttr.st_mtime_nsec));

        // Debug helper
        //DumpEaInformaton(buffer);
        if (__argc < 3)
        {
            goto CleanupExit;
        }
        _tprintf(_T("Copying to: %s\n\n"), __targv[2]);
        targetinfo = open_lxss_file_info(__targv[2]);
        if (targetinfo.fileHandle == NULL)
        {
            _tprintf(_T("[ERROR] Cannot open target file: %s\n"), __targv[2]);
            goto CleanupExit;
        }
        if (targetinfo.fileEaInfo.EaSize > 0)
        {
            _tprintf(_T("[ERROR] EaFile is not empty for target file: %s\n"), __targv[2]);
            goto CleanupExit;
        }

        int x = STATUS_EA_LIST_INCONSISTENT;

        NTSTATUS status;

        NtClose(targetinfo.fileHandle);
        targetinfo.fileHandle = NULL;
        if (!NT_SUCCESS(status = NtOpenFile(
            &targetinfo.fileHandle,
            FILE_GENERIC_WRITE, // includes the required FILE_WRITE_EA access_mask!
            &targetinfo.oa,
            &targetinfo.isb,
            FILE_SHARE_WRITE,
            FILE_SYNCHRONOUS_IO_NONALERT
        )))
        {
            _tprintf(_T("[ERROR] NtOpenFile: 0x%x\n"), status);
            goto CleanupExit;
        }

        // Copy the Extended Attribute structure.
        if (!NT_SUCCESS(status = NtSetEaFile(
            targetinfo.fileHandle,
            &targetinfo.isb,
            srcinfo.buffer,
            srcinfo.bufferLength
        )))
        {
            _tprintf(_T("[ERROR] NtSetEaFile: 0x%x\n"), status);
            goto CleanupExit;
        }
    }

CleanupExit:

    close_lxss_file_info(&srcinfo);
    close_lxss_file_info(&targetinfo);

    //_tprintf(_T("Press any key to continue...\n"));
    //_gettch();
}

VOID DumpEaInformaton(
    _In_ PFILE_FULL_EA_INFORMATION Info
    )
{
    ULONG valueBufferLength;
    PSTR valueBuffer;

    _tprintf(_T("Flags: %d\n"), Info->Flags);
    _tprintf(_T("EaNameLength: %d\n"), Info->EaNameLength);
    _tprintf(_T("EaName: %hs\n"), Info->EaName);

    valueBufferLength = Info->EaValueLength;
    valueBuffer = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, valueBufferLength + 1);
    
    // Make temporary copy of the EaValue
    RtlCopyMemory(
        valueBuffer, 
        Info->EaName + (Info->EaNameLength + 1), 
        valueBufferLength
        );

    // Dump structure
    _tprintf(_T("EaValueLength: %lu\n"), valueBufferLength);
    _tprintf(_T("EaValue: "));

    for (ULONG i = 0; i < valueBufferLength; i++)
    {
        _tprintf(_T("%02X "), 0xFF & valueBuffer[i]);
    }
    _tprintf(_T("\n\n"));

    HeapFree(GetProcessHeap(), 0, valueBuffer);
}
