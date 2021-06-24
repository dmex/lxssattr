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
    ULONG reparseTag;
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
    info.reparseTag = 0;
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
        OBJ_CASE_INSENSITIVE | OBJ_IGNORE_IMPERSONATED_DEVICEMAP, // donot use OBJ_DONT_REPARSE as it will stop at C:
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
        if (status == STATUS_IO_REPARSE_TAG_NOT_HANDLED || status == STATUS_REPARSE_POINT_ENCOUNTERED)
        {
            // file is a REPARSE_POINT, maybe
            // IO_REPARSE_TAG_LX_SYMLINK
            // IO_REPARSE_TAG_LX_FIFO
            // IO_REPARSE_TAG_LX_CHR
            // IO_REPARSE_TAG_LX_BLK 
            // IO_REPARSE_TAG_AF_UNIX
            if (!NT_SUCCESS(status = NtOpenFile(
                &info.fileHandle,
                STANDARD_RIGHTS_READ | FILE_READ_ATTRIBUTES | FILE_READ_EA | FILE_READ_DATA | SYNCHRONIZE, // FILE_GENERIC_READ without FILE_READ_DATA
                &info.oa,
                &info.isb,
                FILE_SHARE_READ,
                FILE_SYNCHRONOUS_IO_NONALERT | FILE_OPEN_REPARSE_POINT
            )))
            {
                _tprintf(_T("[ERROR] NtOpenFile: 0x%x , which is REPARSE_POINT, may be a WslFS symbol link\n"), status);
                goto CleanupExit;
            }
            FILE_ATTRIBUTE_TAG_INFO file_attribute_tag_info;
            if (!NT_SUCCESS(status = GetFileInformationByHandleEx(info.fileHandle, FileAttributeTagInfo, &file_attribute_tag_info, sizeof(FILE_ATTRIBUTE_TAG_INFO))))
            {
                _tprintf(_T("[ERROR] GetFileInformationByHandleEx: 0x%x\n"), status);
                goto CleanupExit;
            }
            info.reparseTag = file_attribute_tag_info.ReparseTag;
        }
        else
        {
            _tprintf(_T("[ERROR] NtOpenFile: 0x%x\n"), status);
            goto CleanupExit;
        }
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

#define _PROGRAM_DESC_ "lxssattr v2.1 by dmex and viruscamp - LXSS extended file attributes viewer and copier"

int __cdecl _tmain()
{
    SetConsoleTitle(_T(_PROGRAM_DESC_));

    if (__argc != 2 && __argc != 3)
    {
        _tprintf(_T("%S\n"), _PROGRAM_DESC_);
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

    if (srcinfo.reparseTag != 0)
    {
        PSTR tag_type = NULL;
        switch (srcinfo.reparseTag) {
        case IO_REPARSE_TAG_LX_SYMLINK: tag_type = "SYMLINK"; break;
        case IO_REPARSE_TAG_LX_FIFO: tag_type = "FIFO"; break;
        case IO_REPARSE_TAG_LX_CHR: tag_type = "CHR"; break;
        case IO_REPARSE_TAG_LX_BLK: tag_type = "BLK"; break;
        case IO_REPARSE_TAG_AF_UNIX: tag_type = "AF_UNIX"; break;
        }
        _tprintf(_T("WslFS reparse point:       %S\n"), tag_type);
    }

    CHAR link_name_buf[MAXIMUM_REPARSE_DATA_BUFFER_SIZE + 1];
    CHAR* link_name = NULL; // UTF8 '\0' terminted

    if (srcinfo.reparseTag == IO_REPARSE_TAG_LX_SYMLINK)
    {
        ULONG junk = 0;
        if (!DeviceIoControl(srcinfo.fileHandle, FSCTL_GET_REPARSE_POINT, NULL, 0, link_name_buf, MAXIMUM_REPARSE_DATA_BUFFER_SIZE, &junk, NULL))
        {
            DWORD errorno = GetLastError();
            _tprintf(_T("[ERROR] DeviceIoControl: 0x%x, Cannot read symlink from reparse_point data\n"), errorno);
        }
        else
        {
            PREPARSE_GUID_DATA_BUFFER reparse_buf = (PREPARSE_GUID_DATA_BUFFER)link_name_buf;
            CHAR* reparse_data = (CHAR*)&reparse_buf->ReparseGuid;
            if (reparse_buf->ReparseDataLength > 4)
            {
                reparse_data[reparse_buf->ReparseDataLength] = '\0';
                link_name = reparse_data + 4;
            }
        }
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
            char filetype = PrintLxattrb(eaInfo);
            if (filetype == 'l')
            {
                DWORD read_size = 0;
                if (!ReadFile(srcinfo.fileHandle, link_name_buf, MAXIMUM_REPARSE_DATA_BUFFER_SIZE, &read_size, NULL))
                {
                    DWORD errorno = GetLastError();
                    _tprintf(_T("[ERROR] ReadFile: 0x%x, Cannot read symlink from file content\n"), errorno);
                }
                else
                {
                    link_name_buf[read_size] = '\0';
                    link_name = link_name_buf;
                }
            }
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
        else if (_stricmp(NTFS_EX_ATTR_LXDEV, eaInfo->EaName) == 0)
        {
            PrintLxdev(eaInfo);
        }
        else
        {
            _tprintf(_T("Unknown EaName:            EaName: %S, EaValueLength: %1u\n"), eaInfo->EaName, eaInfo->EaValueLength);
        }
    }

    if (link_name != NULL)
    {
        // TODO link_name should be UTF-8
        _tprintf(_T("Symlink:                   -> %S\n"), link_name);
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
