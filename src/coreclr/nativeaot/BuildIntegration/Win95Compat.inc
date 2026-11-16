// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

#include "WinLegacyAnsi.inc"

THUNK(BOOL, GetFileAttributesExA, 12, (const char *name, GET_FILEEX_INFO_LEVELS level, void *output))
{
    if (level != GetFileExInfoStandard || output == NULL) {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    /* FindFirstFileA rejects a drive root on Windows 95. FAT roots have
       no directory entry from which to read file sizes or timestamps. */
    if (name != NULL && name[0] != '\0' && name[1] == ':' &&
        (name[2] == '\\' || name[2] == '/') && name[3] == '\0') {
        DWORD attributes = GetFileAttributesA(name);
        if (attributes == INVALID_FILE_ATTRIBUTES) {
            return FALSE;
        }
        WIN32_FILE_ATTRIBUTE_DATA *data = output;
        memset(data, 0, sizeof(*data));
        data->dwFileAttributes = attributes;
        return TRUE;
    }

    WIN32_FIND_DATAA data;
    HANDLE file = FindFirstFileA(name, &data);
    if (file == INVALID_HANDLE_VALUE) {
        return FALSE;
    }
    FindClose(file);

    WIN32_FILE_ATTRIBUTE_DATA *attributes = output;
    attributes->dwFileAttributes = data.dwFileAttributes;
    attributes->ftCreationTime = data.ftCreationTime;
    attributes->ftLastAccessTime = data.ftLastAccessTime;
    attributes->ftLastWriteTime = data.ftLastWriteTime;
    attributes->nFileSizeHigh = data.nFileSizeHigh;
    attributes->nFileSizeLow = data.nFileSizeLow;
    return TRUE;
}

THUNK(BOOL, IsDebuggerPresent, 0, (void))
{
    return FALSE;
}

THUNK(BOOL, IsProcessorFeaturePresent, 4, (DWORD feature))
{
    typedef BOOL (WINAPI *processor_feature_fn)(DWORD);
    processor_feature_fn native = (processor_feature_fn)kernel_proc("IsProcessorFeaturePresent");
    return native != NULL && native(feature);
}

THUNK(BOOL, SetThreadPriorityBoost, 8, (HANDLE thread, BOOL disable))
{
    SetLastError(ERROR_NOT_SUPPORTED);
    return FALSE;
}

THUNK(BOOL, SwitchToThread, 0, (void))
{
    Sleep(0);
    return FALSE;
}

THUNK(HRESULT, CoInitializeEx, 8, (void *reserved, DWORD flags))
{
    typedef HRESULT (WINAPI *initialize_com_fn)(void *, DWORD);
    HMODULE ole32 = GetModuleHandleA("OLE32.DLL");
    initialize_com_fn native = (initialize_com_fn)GetProcAddress(ole32, "CoInitializeEx");
    if (native != NULL) {
        return native(reserved, flags);
    }

    /* Windows 95 installations without CoInitializeEx only expose STA initialization. */
    if (flags != COINIT_APARTMENTTHREADED) {
        return E_NOTIMPL;
    }
    return CoInitialize(reserved);
}
