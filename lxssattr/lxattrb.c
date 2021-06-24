#include "main.h"

char PrintLxattrb(PFILE_FULL_EA_INFORMATION buffer)
{
    LXSS_FILE_EXTENDED_ATTRIBUTES_V1 extendedAttr;

    // Make temporary copy of the structure
    RtlZeroMemory(&extendedAttr, sizeof(LXSS_FILE_EXTENDED_ATTRIBUTES_V1));
    RtlCopyMemory(
        &extendedAttr,
        buffer->EaName + (buffer->EaNameLength + 1),
        sizeof(LXSS_FILE_EXTENDED_ATTRIBUTES_V1)
    );

    _tprintf(_T("LxFS %S:\n"), NTFS_EX_ATTR_LXATTRB);
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

    char filetype = filetypeletter(extendedAttr.st_mode);
    if (filetype == 'b' || filetype == 'c')
    {
        _tprintf(_T("Device type:               %#lx, %#lx\n"),
            MAJOR(extendedAttr.st_rdev), MINOR(extendedAttr.st_rdev)
        );
    }

    _tprintf(_T("Last status change:        %s\n"), UnixStatTime(extendedAttr.st_ctime, extendedAttr.st_ctime_nsec));
    _tprintf(_T("Last file access:          %s\n"), UnixStatTime(extendedAttr.st_atime, extendedAttr.st_atime_nsec));
    _tprintf(_T("Last file modification:    %s\n"), UnixStatTime(extendedAttr.st_mtime, extendedAttr.st_mtime_nsec));

    return filetype;
}
