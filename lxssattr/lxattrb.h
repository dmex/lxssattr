#pragma once

#define NTFS_EX_ATTR_LXATTRB "LXATTRB"

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
} LXSS_FILE_EXTENDED_ATTRIBUTES_V1, * PLXSS_FILE_EXTENDED_ATTRIBUTES_V1;

char PrintLxattrb(PFILE_FULL_EA_INFORMATION buffer);
