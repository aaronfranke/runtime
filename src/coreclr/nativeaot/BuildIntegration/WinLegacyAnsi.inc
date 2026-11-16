// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

#include <limits.h>

THUNK(int, WideCharToMultiByte, 32, (UINT code_page, DWORD flags, const wchar_t *wide,
    int wide_length, char *ansi, int capacity, const char *default_char, BOOL *used_default))
{
    typedef int (WINAPI *convert_fn)(UINT, DWORD, const wchar_t *, int, char *, int, const char *, BOOL *);
    DWORD last_error = GetLastError();
    convert_fn native = (convert_fn)GetProcAddress(GetModuleHandleA("kernel32.dll"), "WideCharToMultiByte");
    if (native == NULL) {
        return 0;
    }

    int count = native(code_page, flags, wide, wide_length, ansi, capacity, default_char, used_default);
    if (count != 0 || code_page != CP_ACP || flags != WC_NO_BEST_FIT_CHARS || default_char != NULL ||
        GetLastError() != ERROR_INVALID_FLAGS || LOWORD(GetVersion()) != 4) {
        return count;
    }

    if (wide == NULL || wide_length < -1 || wide_length == 0 || capacity < 0 ||
        (capacity != 0 && (ansi == NULL || (const void *)wide == ansi))) {
        SetLastError(ERROR_INVALID_PARAMETER);
        return 0;
    }

    CPINFO info;
    if (!GetCPInfo(CP_ACP, &info)) {
        return 0;
    }

    /* Windows 95 and NT 4 reject WC_NO_BEST_FIT_CHARS. Keep only conversions that
       round-trip exactly, using the system default for each unmappable code unit. */
    int replacement_length = info.DefaultChar[1] == 0 ? 1 : 2;
    BOOL replaced = FALSE;
    for (int index = 0; wide_length == -1 || index < wide_length; ++index) {
        char bytes[2];
        int length = native(CP_ACP, 0, wide + index, 1, bytes, sizeof(bytes), NULL, NULL);
        if (length == 0) {
            return 0;
        }

        wchar_t decoded;
        const char *encoded = bytes;
        if (MultiByteToWideChar(CP_ACP, 0, bytes, length, &decoded, 1) != 1 || decoded != wide[index]) {
            encoded = (const char *)info.DefaultChar;
            length = replacement_length;
            replaced = TRUE;
        }

        if (length > INT_MAX - count || (capacity != 0 && length > capacity - count)) {
            SetLastError(ERROR_INSUFFICIENT_BUFFER);
            return 0;
        }

        if (capacity != 0) {
            memcpy(ansi + count, encoded, length);
        }
        count += length;

        if (wide_length == -1 && wide[index] == L'\0') {
            break;
        }
    }

    if (used_default != NULL) {
        *used_default = replaced;
    }
    SetLastError(last_error);
    return count;
}
