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

void __cdecl _tmain()
{
    NTSTATUS status;
    IO_STATUS_BLOCK isb;
    OBJECT_ATTRIBUTES oa;
    UNICODE_STRING fileName;
    HANDLE fileHandle = NULL;
    FILE_EA_INFORMATION fileEaInfo = { 0 };
    PFILE_FULL_EA_INFORMATION buffer = NULL;
    ULONG bufferLength = 0;

    SetConsoleTitle(_T("lxssattr v1.1 by dmex - LXSS extended file attributes viewer"));

    if (__argc != 2)
    {
        _tprintf(_T("Invalid arguments.\n"));
        //_gettch();
        return;
    }

    _tprintf(_T("Querying: %s\n\n"), __targv[1]);

    LxssLoadUsersFile();
    LxssLoadGroupsFile();

    __try
    {
        if (!NT_SUCCESS(status = RtlDosPathNameToNtPathName_U_WithStatus(
            __targv[1],
            &fileName,
            NULL,
            NULL
            )))
        {
            _tprintf(_T("[ERROR] RtlDosPathNameToNtPathName: 0x%x\n"), status);
            __leave;
        }

        InitializeObjectAttributes(
            &oa,
            &fileName,
            OBJ_CASE_INSENSITIVE,
            NULL,
            NULL
            );

        if (!NT_SUCCESS(status = NtOpenFile(
            &fileHandle, 
            FILE_GENERIC_READ, // includes the required FILE_READ_EA access_mask!
            &oa,
            &isb,
            FILE_SHARE_READ,
            FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE
            )))
        {
            _tprintf(_T("[ERROR] NtOpenFile: 0x%x\n"), status);
            __leave;
        }

        // Note: If you don't want to use NtOpenFile, InitializeObjectAttributes or RtlDosPathNameToNtPathName_U_WithStatus...
        // Just remove the above code and use CreateFile.
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
            fileHandle,
            &isb,
            &fileEaInfo,
            sizeof(FILE_EA_INFORMATION),
            FileEaInformation
            )))
        {
            _tprintf(_T("[ERROR] NtQueryInformationFile: 0x%x\n"), status);
            __leave;
        }

        // Allocate memory for the Extended Attribute
        bufferLength = fileEaInfo.EaSize;
        buffer = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, bufferLength + 1);

        // Query the Extended Attribute structure.
        if (!NT_SUCCESS(status = NtQueryEaFile(
            fileHandle, 
            &isb,
            buffer, 
            bufferLength,
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
            __leave;
        }

        if (_stricmp("LXATTRB", buffer->EaName))
        {
            _tprintf(_T("[ERROR] LXATTRB not found.\n"));
            __leave;
        }
        else
        {
            LXSS_FILE_EXTENDED_ATTRIBUTES_V1 extendedAttr;

            // Make temporary copy of the structure
            RtlZeroMemory(&extendedAttr, sizeof(LXSS_FILE_EXTENDED_ATTRIBUTES_V1));
            RtlCopyMemory(
                &extendedAttr,
                buffer->EaName + (buffer->EaNameLength + 1),
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
        }
    }
    __finally
    {
        if (fileHandle)
        {
            NtClose(fileHandle);
        }

        if (fileName.Buffer)
        {
            RtlFreeHeap(GetProcessHeap(), 0, fileName.Buffer);
        }

        if (buffer)
        {
            HeapFree(GetProcessHeap(), 0, buffer);
        }
    }

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
    memcpy(
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
