#include "main.h"

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

PFILE_FULL_EA_INFORMATION NextEaInfo(PFILE_FULL_EA_INFORMATION buffer)
{
    if (buffer->NextEntryOffset != 0)
    {
        return (PFILE_FULL_EA_INFORMATION)((CHAR*)buffer + buffer->NextEntryOffset);
    }
    else
    {
        return NULL;
    }
}

LXSS_FILE_INFO LxssFileInfo()
{
    LXSS_FILE_INFO info;
    info.fileName.Buffer = NULL;
    info.fileName.Length = 0;
    info.fileHandle = NULL;
    info.fileEaInfo.EaSize = 0;
    info.buffer = NULL;
    info.bufferLength = 0;
    return info;
}

LXSS_FILE_INFO OpenLxssFileInfo(PWSTR filename)
{
    NTSTATUS status;

    LXSS_FILE_INFO info = LxssFileInfo();

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
        if (status == STATUS_IO_REPARSE_TAG_NOT_HANDLED)
            _tprintf(_T("[ERROR] NtOpenFile: 0x%x may be a WslFS symbol link\n"), status);
        else
            _tprintf(_T("[ERROR] NtOpenFile: 0x%x\n"), status);
        goto CleanupExit;
    }

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
        FALSE, // read all ea entries to buffer
        NULL,
        0,
        NULL,
        FALSE
    )))
    {
        //if (status == STATUS_NO_MORE_EAS)
        if (status == STATUS_NO_EAS_ON_FILE) goto CleanupExit;
        _tprintf(_T("[ERROR] NtQueryEaFile: 0x%x\n"), status);
        goto CleanupExit;
    }

CleanupExit:
    return info;
}

void CloseLxssFileInfo(LXSS_FILE_INFO *info)
{
    if (info->fileHandle)
        NtClose(info->fileHandle);

    if (info->fileName.Buffer)
        RtlFreeHeap(GetProcessHeap(), 0, info->fileName.Buffer);

    if (info->buffer)
        HeapFree(GetProcessHeap(), 0, info->buffer);
}

int __cdecl _tmain()
{
    SetConsoleTitle(_T("lxssattr v2.0 by dmex and viruscamp - LXSS extended file attributes viewer and copier"));

    if (__argc != 2 && __argc != 3)
    {
        _tprintf(_T("lxssattr FILENAME\n"));
        _tprintf(_T("\tto show LXATTRB(LxFS) and $LXUID, $LXGID, $LXMOD (WslFS)\n"));
        _tprintf(_T("lxssattr SOURCE_FILENAME TARGET_FILENAME\n"));
        _tprintf(_T("\tto copy EaFile(includes LXATTRB or $LXUID + $LXGID + $LXMOD ) from SOURCE_FILENAME to TARGET_FILENAME\n"));
        return EXIT_SUCCESS;
    }

    int exit_code = EXIT_FAILURE;

    LxssLoadUsersFile();
    LxssLoadGroupsFile();

    LXSS_FILE_INFO srcinfo = LxssFileInfo();
    LXSS_FILE_INFO targetinfo = LxssFileInfo();

    _tprintf(_T("Querying: %s\n\n"), __targv[1]);
    srcinfo = OpenLxssFileInfo(__targv[1]);
    if (srcinfo.fileHandle == NULL)
    {
        _tprintf(_T("[ERROR] Cannot open source file: %s\n"), __targv[1]);
        goto CleanupExit;
    }

    PFILE_FULL_EA_INFORMATION pEaLxattrb = NULL;
    PFILE_FULL_EA_INFORMATION pEaLxuid = NULL;
    PFILE_FULL_EA_INFORMATION pEaLxgid = NULL;
    PFILE_FULL_EA_INFORMATION pEaLxmod = NULL;
    for (PFILE_FULL_EA_INFORMATION eaInfo = srcinfo.buffer; eaInfo != NULL; eaInfo = NextEaInfo(eaInfo))
    {
        if (_stricmp(NTFS_EX_ATTR_LXATTRB, eaInfo->EaName) == 0)
        {
            pEaLxattrb = eaInfo;
            PrintLxattrb(eaInfo);
        }
        else if (_stricmp(NTFS_EX_ATTR_LXUID, eaInfo->EaName) == 0)
        {
            pEaLxuid = eaInfo;
            PrintLxuid(eaInfo);
        }
        else if(_stricmp(NTFS_EX_ATTR_LXGID, eaInfo->EaName) == 0)
        {
            pEaLxgid = eaInfo;
            PrintLxgid(eaInfo);
        }
        else if(_stricmp(NTFS_EX_ATTR_LXMOD, eaInfo->EaName) == 0)
        {
            pEaLxmod = eaInfo;
            PrintLxmod(eaInfo);
        }
    }

    if (pEaLxattrb == NULL && (pEaLxuid == NULL || pEaLxgid == NULL || pEaLxmod == NULL))
    {
        _tprintf(_T("[ERROR] LXATTRB or $LXUID + $LXGID + $LXMOD not found.\n"));
        goto CleanupExit;
    }
    else
    {
        if (__argc < 3)
        {
            exit_code = EXIT_SUCCESS;
            goto CleanupExit;
        }
        _tprintf(_T("Copying to: %s\n\n"), __targv[2]);
        targetinfo = OpenLxssFileInfo(__targv[2]);
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
        NtClose(targetinfo.fileHandle);
        targetinfo.fileHandle = NULL;

        NTSTATUS status;
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
        exit_code = EXIT_SUCCESS;
        goto CleanupExit;
    }

CleanupExit:

    CloseLxssFileInfo(&srcinfo);
    CloseLxssFileInfo(&targetinfo);

    //_tprintf(_T("Press any key to continue...\n"));
    //_gettch();

    return exit_code;
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
