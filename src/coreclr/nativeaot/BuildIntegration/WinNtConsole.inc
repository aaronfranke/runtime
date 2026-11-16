// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

static FARPROC legacy_console_kernel_proc(const char *name)
{
    return GetProcAddress(GetModuleHandleA("kernel32.dll"), name);
}

// Reuse the byte-stream renderer while retaining NT's native Unicode input.
// Native virtual-terminal processing remains preferred where available.
#define WIN_LEGACY_CONSOLE_KERNEL_PROC legacy_console_kernel_proc
#include "WinLegacyConsoleOutput.inc"
#undef WIN_LEGACY_CONSOLE_KERNEL_PROC

THUNK(BOOL, WriteFile, 20, (HANDLE file, const void *buffer, DWORD bytes, DWORD *written, OVERLAPPED *overlapped))
{
    typedef BOOL (WINAPI *write_file_fn)(HANDLE, const void *, DWORD, DWORD *, OVERLAPPED *);
    write_file_fn native = (write_file_fn)legacy_console_kernel_proc("WriteFile");
    DWORD error = GetLastError();
    if (overlapped == NULL && written != NULL && file == GetStdHandle(STD_OUTPUT_HANDLE)) {
        BOOL handled;
        BOOL result = terminal_write(file, buffer, bytes, written, &handled);
        if (handled) {
            return result;
        }
    }
    SetLastError(error);
    return native(file, buffer, bytes, written, overlapped);
}
