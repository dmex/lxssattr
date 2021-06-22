#pragma once

#define NTFS_EX_ATTR_LXUID "$LXUID"
#define NTFS_EX_ATTR_LXGID "$LXGID"
#define NTFS_EX_ATTR_LXMOD "$LXMOD"
#define NTFS_EX_ATTR_LXDEV "$LXDEV"

void PrintLxuid(PFILE_FULL_EA_INFORMATION buffer);
void PrintLxgid(PFILE_FULL_EA_INFORMATION buffer);
void PrintLxmod(PFILE_FULL_EA_INFORMATION buffer);