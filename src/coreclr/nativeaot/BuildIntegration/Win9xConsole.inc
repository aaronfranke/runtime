// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

#define WIN_LEGACY_CONSOLE_KERNEL_PROC kernel_proc
#define WIN_LEGACY_CONSOLE_FORCE is_win9x()
#include "WinLegacyConsoleOutput.inc"
#undef WIN_LEGACY_CONSOLE_FORCE
#undef WIN_LEGACY_CONSOLE_KERNEL_PROC

static BOOL console_input_w(HANDLE handle, INPUT_RECORD *records, DWORD length, DWORD *read, BOOL peek)
{
    if (!is_win9x()) {
        typedef BOOL (WINAPI *read_input_fn)(HANDLE, INPUT_RECORD *, DWORD, DWORD *);
        read_input_fn native = (read_input_fn)kernel_proc(peek ? "PeekConsoleInputW" : "ReadConsoleInputW");
        return native(handle, records, length, read);
    }

    BOOL result = peek ? PeekConsoleInputA(handle, records, length, read) :
        ReadConsoleInputA(handle, records, length, read);
    if (result) {
        UINT code_page = GetConsoleCP();
        for (DWORD i = 0; i < *read; ++i) {
            if (records[i].EventType != KEY_EVENT) {
                continue;
            }
            KEY_EVENT_RECORD *key = &records[i].Event.KeyEvent;
            CHAR encoded = key->uChar.AsciiChar;
            wchar_t decoded = 0;
            if (encoded != 0 && !MultiByteToWideChar(code_page, 0, &encoded, 1, &decoded, 1)) {
                decoded = 0xfffd;
            }
            key->uChar.UnicodeChar = decoded;
        }
    }
    return result;
}

THUNK(BOOL, ReadConsoleInputW, 16, (HANDLE handle, INPUT_RECORD *records, DWORD length, DWORD *read))
{
    return console_input_w(handle, records, length, read, FALSE);
}

THUNK(BOOL, PeekConsoleInputW, 16, (HANDLE handle, INPUT_RECORD *records, DWORD length, DWORD *read))
{
    return console_input_w(handle, records, length, read, TRUE);
}
