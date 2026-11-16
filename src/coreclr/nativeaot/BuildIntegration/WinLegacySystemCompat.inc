// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

#ifndef CONTEXT_XSTATE
/* Some MinGW headers omit CONTEXT_XSTATE on x86. */
#if defined(_WIN64)
#define CONTEXT_XSTATE (CONTEXT_AMD64 | 0x00000040L)
#else
#define CONTEXT_XSTATE (CONTEXT_i386 | 0x00000040L)
#endif
#endif

static FARPROC kernel_proc(const char *name)
{
    return GetProcAddress(GetModuleHandleW(L"kernel32.dll"), name);
}

#ifndef WINNT5_REQUIRE_NATIVE_DLL_SEARCH
THUNK(HMODULE, LoadLibraryExW, 12, (LPCWSTR name, HANDLE file, DWORD flags))
{
    typedef HMODULE (WINAPI *load_library_fn)(LPCWSTR, HANDLE, DWORD);
    HMODULE kernel = GetModuleHandleW(L"kernel32.dll");
    load_library_fn load_library = (load_library_fn)GetProcAddress(kernel, "LoadLibraryExW");
    if (flags != LOAD_LIBRARY_SEARCH_SYSTEM32 || file != NULL || name == NULL ||
        GetProcAddress(kernel, "AddDllDirectory") != NULL) {
        return load_library(name, file, flags);
    }

    /* Windows 7 needs KB2533623 for the search flag. Use the system directory
       explicitly on older installations to preserve the restricted search. */
    UINT name_length = 0;
    for (; name[name_length] != L'\0'; ++name_length) {
        if (name[name_length] == L'\\' || name[name_length] == L'/' || name[name_length] == L':') {
            return load_library(name, file, flags);
        }
    }
    WCHAR path[MAX_PATH];
    UINT directory_length = GetSystemDirectoryW(path, MAX_PATH);
    if (directory_length == 0) {
        return NULL;
    }
    if (directory_length >= MAX_PATH || name_length >= MAX_PATH - directory_length - 1) {
        SetLastError(ERROR_INSUFFICIENT_BUFFER);
        return NULL;
    }
    path[directory_length++] = L'\\';
    for (UINT i = 0; i <= name_length; ++i) {
        path[directory_length + i] = name[i];
    }
    return load_library(path, NULL, 0);
}
#endif

/* The XState APIs arrived in Windows 7 SP1. A standard CONTEXT remains
   sufficient for the runtime on Windows 7 RTM and XP x64. */
THUNK(BOOL, CopyContext, 12, (CONTEXT *to, DWORD flags, CONTEXT *from))
{
    typedef BOOL (WINAPI *copy_context_fn)(CONTEXT *, DWORD, CONTEXT *);
    copy_context_fn copy = (copy_context_fn)kernel_proc("CopyContext");
    if (copy != NULL) {
        return copy(to, flags, from);
    }
    if ((flags & CONTEXT_XSTATE) == CONTEXT_XSTATE) {
        SetLastError(ERROR_NOT_SUPPORTED);
        return FALSE;
    }
    *to = *from;
    to->ContextFlags = flags;
    return TRUE;
}

THUNK(BOOL, InitializeContext, 16, (void *buffer, DWORD flags, CONTEXT **context, DWORD *size))
{
    typedef BOOL (WINAPI *initialize_context_fn)(void *, DWORD, CONTEXT **, DWORD *);
    initialize_context_fn initialize = (initialize_context_fn)kernel_proc("InitializeContext");
    if (initialize != NULL) {
        return initialize(buffer, flags, context, size);
    }
    if ((flags & CONTEXT_XSTATE) == CONTEXT_XSTATE) {
        SetLastError(ERROR_NOT_SUPPORTED);
        return FALSE;
    }

    const ULONG_PTR alignment = __alignof__(CONTEXT);
    const DWORD required = sizeof(CONTEXT) + alignment - 1;
    if (buffer == NULL || *size < required) {
        *size = required;
        SetLastError(ERROR_INSUFFICIENT_BUFFER);
        return FALSE;
    }
    *context = (CONTEXT *)(((ULONG_PTR)buffer + alignment - 1) & ~(alignment - 1));
    memset(*context, 0, sizeof(**context));
    (*context)->ContextFlags = flags;
    return TRUE;
}

THUNK(DWORD64, GetEnabledXStateFeatures, 0, (void))
{
    typedef DWORD64 (WINAPI *get_xstate_fn)(void);
    get_xstate_fn get_features = (get_xstate_fn)kernel_proc("GetEnabledXStateFeatures");
    return get_features == NULL ? 0 : get_features();
}

THUNK(BOOL, SetXStateFeaturesMask, 12, (CONTEXT *context, DWORD64 features))
{
    typedef BOOL (WINAPI *set_xstate_fn)(CONTEXT *, DWORD64);
    set_xstate_fn set_mask = (set_xstate_fn)kernel_proc("SetXStateFeaturesMask");
    if (set_mask != NULL) {
        return set_mask(context, features);
    }

    /* An OS without XState ignores requests for unavailable registers. */
    if ((context->ContextFlags & CONTEXT_XSTATE) == CONTEXT_XSTATE) {
        SetLastError(ERROR_NOT_SUPPORTED);
        return FALSE;
    }
    return TRUE;
}

THUNK(void *, LocateXStateFeature, 12, (CONTEXT *context, DWORD feature, DWORD *length))
{
    typedef void *(WINAPI *locate_xstate_fn)(CONTEXT *, DWORD, DWORD *);
    locate_xstate_fn locate = (locate_xstate_fn)kernel_proc("LocateXStateFeature");
    if (locate != NULL) {
        return locate(context, feature, length);
    }
    if (length != NULL) {
        *length = 0;
    }
    return NULL;
}
