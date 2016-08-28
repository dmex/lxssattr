#pragma once

// This header file provides access to NT APIs.

// Static link against ntdll.lib from the Windows SDK.
#pragma comment(lib, "ntdll.lib")

// https://msdn.microsoft.com/en-us/library/windows/hardware/ff728840.aspx
typedef enum _FILE_INFORMATION_CLASS2 // Note: Structure renamed due to Windows SDK conflict.
{
    FileDirectoryInformation_2 = 1, // Note: Field renamed due to Windows SDK conflict.
    FileFullDirectoryInformation,
    FileBothDirectoryInformation,
    FileBasicInformation,
    FileStandardInformation,
    FileInternalInformation,
    FileEaInformation,
    FileAccessInformation,
    FileNameInformation,
    FileRenameInformation,
    FileLinkInformation,
    FileNamesInformation,
    FileDispositionInformation,
    FilePositionInformation,
    FileFullEaInformation,
    FileModeInformation,
    FileAlignmentInformation,
    FileAllInformation,
    FileAllocationInformation,
    FileEndOfFileInformation,
    FileAlternateNameInformation,
    FileStreamInformation,
    FilePipeInformation,
    FilePipeLocalInformation,
    FilePipeRemoteInformation,
    FileMailslotQueryInformation,
    FileMailslotSetInformation,
    FileCompressionInformation,
    FileObjectIdInformation,
    FileCompletionInformation,
    FileMoveClusterInformation,
    FileQuotaInformation,
    FileReparsePointInformation,
    FileNetworkOpenInformation,
    FileAttributeTagInformation,
    FileTrackingInformation,
    FileIdBothDirectoryInformation,
    FileIdFullDirectoryInformation,
    FileValidDataLengthInformation,
    FileShortNameInformation,
    FileIoCompletionNotificationInformation,
    FileIoStatusBlockRangeInformation,
    FileIoPriorityHintInformation,
    FileSfioReserveInformation,
    FileSfioVolumeInformation,
    FileHardLinkInformation,
    FileProcessIdsUsingFileInformation,
    FileNormalizedNameInformation,
    FileNetworkPhysicalNameInformation,
    FileIdGlobalTxDirectoryInformation,
    FileIsRemoteDeviceInformation,
    FileUnusedInformation,
    FileNumaNodeInformation,
    FileStandardLinkInformation,
    FileRemoteProtocolInformation,
    FileRenameInformationBypassAccessCheck,
    FileLinkInformationBypassAccessCheck,
    FileVolumeNameInformation,
    FileIdInformation,
    FileIdExtdDirectoryInformation,
    FileReplaceCompletionInformation,
    FileHardLinkFullIdInformation,
    FileIdExtdBothDirectoryInformation,
    FileMaximumInformation
} FILE_INFORMATION_CLASS2, *PFILE_INFORMATION_CLASS2;

// https://msdn.microsoft.com/en-us/library/windows/hardware/ff545773.aspx
typedef struct _FILE_EA_INFORMATION
{
    ULONG EaSize;          // Specifies the combined length, in bytes, of the extended attributes for the file.
} FILE_EA_INFORMATION, *PFILE_EA_INFORMATION;

// https://msdn.microsoft.com/en-us/library/windows/hardware/ff545793.aspx
typedef struct _FILE_FULL_EA_INFORMATION
{
    ULONG NextEntryOffset; // The offset of the next FILE_FULL_EA_INFORMATION-type entry. This member is zero if no other entries follow this one.
    UCHAR Flags;           // Can be zero or can be set with FILE_NEED_EA, indicating that the file to which the EA belongs cannot be interpreted without understanding the associated extended attributes.
    UCHAR EaNameLength;    // The length in bytes of the EaName array. This value does not include a null-terminator to EaName.
    USHORT EaValueLength;  // The length in bytes of each EA value in the array.
    CHAR EaName[1];        // An array of characters naming the EA for this entry.
} FILE_FULL_EA_INFORMATION, *PFILE_FULL_EA_INFORMATION;

// https://msdn.microsoft.com/en-us/library/windows/hardware/ff540295.aspx
typedef struct _FILE_GET_EA_INFORMATION
{
    ULONG NextEntryOffset; // Offset, in bytes, of the next FILE_GET_EA_INFORMATION-typed entry. This member is zero if no other entries follow this one.
    UCHAR EaNameLength;    // Length, in bytes, of the EaName array. This value does not include a NULL terminator.
    CHAR EaName[1];        // Specifies the first character of the name of the extended attribute to be queried. This is followed in memory by the remainder of the string.
} FILE_GET_EA_INFORMATION, *PFILE_GET_EA_INFORMATION;

NTSYSAPI
NTSTATUS 
NTAPI
NtQueryInformationFile( // https://msdn.microsoft.com/en-us/library/windows/hardware/ff567052.aspx
    _In_  HANDLE                 FileHandle,
    _Out_ PIO_STATUS_BLOCK       IoStatusBlock,
    _Out_ PVOID                  FileInformation,
    _In_  ULONG                  Length,
    _In_  FILE_INFORMATION_CLASS2 FileInformationClass
    );

NTSYSAPI
NTSTATUS 
NTAPI 
NtQueryEaFile( // https://msdn.microsoft.com/en-us/library/windows/hardware/ff961907.aspx
    _In_     HANDLE           FileHandle,
    _Out_    PIO_STATUS_BLOCK IoStatusBlock,
    _Out_    PVOID            Buffer,
    _In_     ULONG            Length,
    _In_     BOOLEAN          ReturnSingleEntry,
    _In_opt_ PVOID            EaList,
    _In_     ULONG            EaListLength,
    _In_opt_ PULONG           EaIndex,
    _In_     BOOLEAN          RestartScan
    );

NTSYSAPI
NTSTATUS 
NTAPI 
NtSetEaFile( // https://msdn.microsoft.com/en-us/library/windows/hardware/ff961908.aspx
    _In_   HANDLE FileHandle,
    _Out_  PIO_STATUS_BLOCK IoStatusBlock,
    _In_   PVOID Buffer,
    _In_   ULONG Length
    );

NTSYSAPI
BOOLEAN
NTAPI
RtlFreeHeap( // https://msdn.microsoft.com/en-us/library/windows/hardware/ff552276(v=vs.85).aspx
    _In_ PVOID HeapHandle,
    _In_opt_ ULONG Flags,
    _Frees_ptr_opt_ PVOID BaseAddress
    );

// Below code copied from Process Hacker (licenced under the GPL3).
// https://wj32.org/processhacker/

typedef struct _RTL_RELATIVE_NAME_U
{
    UNICODE_STRING RelativeName;
    HANDLE ContainingDirectory;
    PVOID CurDirRef;
} RTL_RELATIVE_NAME_U, *PRTL_RELATIVE_NAME_U;

NTSYSAPI
NTSTATUS
NTAPI
RtlDosPathNameToNtPathName_U_WithStatus(
    _In_ PWSTR DosFileName,
    _Out_ PUNICODE_STRING NtFileName,
    _Out_opt_ PWSTR *FilePart,
    _Out_opt_ PRTL_RELATIVE_NAME_U RelativeName
    );

