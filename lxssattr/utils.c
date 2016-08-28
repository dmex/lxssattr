#include "main.h"

VOID __cdecl StringFormatColor(
    _In_ WORD color,
    _In_ _Printf_format_string_ PTSTR Format,
    ...)
{
    va_list arglist;
    INT length = 0;
    PTSTR string = NULL;

    WORD wOldColorAttrs = 0;
    CONSOLE_SCREEN_BUFFER_INFO csbiInfo = { 0 };

    va_start(arglist, Format);

    // _vsctprintf doesn't count the terminating '\0' so we +1
    length = _vsctprintf(Format, arglist) + 1;

    if (length < 0)
    {
        va_end(arglist);
        return;
    }

    string = (TCHAR*)malloc((length * sizeof(TCHAR)) + 1);
    memset(string, 0, (length * sizeof(TCHAR)) + 1);
    _vstprintf_s(
        string,
        length,
        Format,
        arglist);
    va_end(arglist);

    // Save the current console colors
    GetConsoleScreenBufferInfo(GetStdHandle(STD_OUTPUT_HANDLE), &csbiInfo);
    wOldColorAttrs = csbiInfo.wAttributes;
    // Set the new console colors
    SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), color);

    _tprintf_s(_T("%s"), string);

    // Reset the current console colors
    SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), wOldColorAttrs);

    free(string);
}