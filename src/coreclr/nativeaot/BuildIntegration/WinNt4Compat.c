// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <windows.h>
#include <winternl.h>
#include <objbase.h>
#include <wincrypt.h>
#include <psapi.h>
#include <string.h>

/* The x86 COFF aliases satisfy imported and direct stdcall
   references while using the unmodified MSVC-built runtime archives. */
#define THUNK(ret, name, bytes, args) \
    ret WINAPI compat_##name args __asm__("_" #name "@" #bytes); \
    ret (WINAPI *const iat_##name) args __asm__("__imp__" #name "@" #bytes) = compat_##name; \
    ret WINAPI compat_##name args

#include "WinNtConsole.inc"

#include "WinLegacyAnsi.inc"

THUNK(BOOL, IsWow64Process, 8, (HANDLE process, PBOOL wow64))
{
    typedef BOOL (WINAPI *is_wow64_fn)(HANDLE, PBOOL);
    is_wow64_fn native = (is_wow64_fn)GetProcAddress(GetModuleHandleA("kernel32.dll"), "IsWow64Process");
    if (native != NULL) {
        return native(process, wow64);
    }
    if (wow64 == NULL) {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    /* The targeted pre-WOW64 x86 kernels cannot host 64-bit processes.
       Do not make that assumption for a 64-bit build without the real API. */
    if (sizeof(void *) != 4) {
        SetLastError(ERROR_CALL_NOT_IMPLEMENTED);
        return FALSE;
    }
    DWORD exit_code;
    if (!GetExitCodeProcess(process, &exit_code)) {
        return FALSE;
    }
    *wow64 = FALSE;
    return TRUE;
}

THUNK(DWORD, GetProcessId, 4, (HANDLE process))
{
    typedef DWORD (WINAPI *get_process_id_fn)(HANDLE);
    get_process_id_fn native = (get_process_id_fn)GetProcAddress(GetModuleHandleA("kernel32.dll"), "GetProcessId");
    if (native != NULL) {
        return native(process);
    }

    /* NT 4 and Windows 2000 lack GetProcessId. */
    typedef NTSTATUS (NTAPI *query_process_fn)(HANDLE, PROCESSINFOCLASS, void *, ULONG, ULONG *);
    typedef ULONG (NTAPI *status_error_fn)(NTSTATUS);
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    query_process_fn query = (query_process_fn)GetProcAddress(ntdll, "NtQueryInformationProcess");
    status_error_fn status_error = (status_error_fn)GetProcAddress(ntdll, "RtlNtStatusToDosError");
    if (query == NULL || status_error == NULL) {
        SetLastError(ERROR_CALL_NOT_IMPLEMENTED);
        return 0;
    }

    PROCESS_BASIC_INFORMATION info;
    NTSTATUS status = query(process, ProcessBasicInformation, &info, sizeof(info), NULL);
    if (status < 0) {
        SetLastError(status_error(status));
        return 0;
    }
    return (DWORD)info.UniqueProcessId;
}

THUNK(LONG, RtlGetVersion, 4, (OSVERSIONINFOW *version))
{
    typedef LONG (WINAPI *get_version_fn)(OSVERSIONINFOW *);
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    get_version_fn native = (get_version_fn)GetProcAddress(ntdll, "RtlGetVersion");
    if (native != NULL) {
        return native(version);
    }

    /* NT 4 exposes the version information through GetVersionExW. */
    if (version == NULL || (version->dwOSVersionInfoSize != sizeof(*version) &&
        version->dwOSVersionInfoSize != sizeof(OSVERSIONINFOEXW))) {
        return (LONG)0xc000000d;
    }
    return GetVersionExW(version) ? 0 : (LONG)0xc0000001;
}

THUNK(DWORD, GetFullPathNameW, 16, (const wchar_t *name, DWORD capacity, wchar_t *buffer, wchar_t **file_part))
{
    typedef DWORD (WINAPI *get_full_path_fn)(const wchar_t *, DWORD, wchar_t *, wchar_t **);
    get_full_path_fn native = (get_full_path_fn)GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "GetFullPathNameW");
    SIZE_T length = name == NULL ? 0 : (SIZE_T)lstrlenW(name);
    if (length == 0 || name[length - 1] != L'/' || (GetVersion() & 0x800000ff) != 4) {
        return native(name, capacity, buffer, file_part);
    }

    /* NT 4 drops a trailing forward slash. Normalize it before the native
       query so directory entries (including ZIP extraction) retain their kind.
       Forwarding the query preserves required sizes and output file-part pointers. */
    HANDLE heap = GetProcessHeap();
    wchar_t *normalized = HeapAlloc(heap, 0, (length + 1) * sizeof(wchar_t));
    if (normalized == NULL) {
        SetLastError(ERROR_NOT_ENOUGH_MEMORY);
        return 0;
    }
    for (SIZE_T i = 0; i < length; i++) {
        normalized[i] = name[i] == L'/' ? L'\\' : name[i];
    }
    normalized[length] = L'\0';
    DWORD result = native(normalized, capacity, buffer, file_part);
    DWORD error = GetLastError();
    HeapFree(heap, 0, normalized);
    SetLastError(error);
    return result;
}

static BOOL random_bytes(BYTE *bytes, DWORD length)
{
    HCRYPTPROV provider;
    if (!CryptAcquireContextW(&provider, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
        return FALSE;
    }
    BOOL result = CryptGenRandom(provider, length, bytes);
    CryptReleaseContext(provider, 0);
    return result;
}

THUNK(LONG, BCryptGenRandom, 16, (void *algorithm, BYTE *bytes, ULONG length, ULONG flags))
{
    if (algorithm != NULL || flags != 2) {
        return (LONG)0xc000000d;
    }
    return random_bytes(bytes, length) ? 0 : (LONG)0xc0000001;
}

static volatile LONG pointer_cookie;

static ULONG_PTR cookie(void)
{
    LONG value = pointer_cookie;
    if (value == 0) {
        if (!random_bytes((BYTE *)&value, sizeof(value))) {
            TerminateProcess(GetCurrentProcess(), 1);
        }
        if (!value) {
            value = 1;
        }
        LONG previous = InterlockedCompareExchange(&pointer_cookie, value, 0);
        if (previous) {
            value = previous;
        }
    }
    return (ULONG_PTR)value;
}

THUNK(void *, EncodePointer, 4, (void *ptr))
{
    return (void *)((ULONG_PTR)ptr ^ cookie());
}

THUNK(void *, DecodePointer, 4, (void *ptr))
{
    return (void *)((ULONG_PTR)ptr ^ cookie());
}

THUNK(void, GetCurrentProcessorNumberEx, 4, (PROCESSOR_NUMBER *processor))
{
    typedef void (WINAPI *get_processor_ex_fn)(PROCESSOR_NUMBER *);
    typedef DWORD (WINAPI *get_processor_fn)(void);
    HMODULE kernel = GetModuleHandleA("kernel32.dll");
    get_processor_ex_fn get_processor_ex = (get_processor_ex_fn)GetProcAddress(kernel, "GetCurrentProcessorNumberEx");
    if (get_processor_ex != NULL) {
        get_processor_ex(processor);
        return;
    }

    /* NT 4 and NT 5 have neither query. Use one cache partition on those systems. */
    get_processor_fn get_processor = (get_processor_fn)GetProcAddress(kernel, "GetCurrentProcessorNumber");
    *processor = (PROCESSOR_NUMBER){0};
    if (get_processor != NULL) {
        processor->Number = (BYTE)get_processor();
    }
}

THUNK(BOOL, InitializeCriticalSectionEx, 12, (CRITICAL_SECTION *section, DWORD count, DWORD flags))
{
    return InitializeCriticalSectionAndSpinCount(section, count);
}

THUNK(void, InitializeSListHead, 4, (SLIST_HEADER *header))
{
    memset(header, 0, sizeof(*header));
}

/* Use FLS when the host exports it. Windows NT 4 has only TLS,
   which does not deliver thread or fiber destruction callbacks. */
THUNK(DWORD, FlsAlloc, 4, (PFLS_CALLBACK_FUNCTION callback))
{
    typedef DWORD (WINAPI *fls_fn)(PFLS_CALLBACK_FUNCTION);
    fls_fn native = (fls_fn)GetProcAddress(GetModuleHandleA("kernel32.dll"), "FlsAlloc");
    return native != NULL ? native(callback) : TlsAlloc();
}

THUNK(BOOL, FlsFree, 4, (DWORD index))
{
    typedef BOOL (WINAPI *fls_fn)(DWORD);
    fls_fn native = (fls_fn)GetProcAddress(GetModuleHandleA("kernel32.dll"), "FlsFree");
    return native != NULL ? native(index) : TlsFree(index);
}

THUNK(void *, FlsGetValue, 4, (DWORD index))
{
    typedef void * (WINAPI *fls_fn)(DWORD);
    fls_fn native = (fls_fn)GetProcAddress(GetModuleHandleA("kernel32.dll"), "FlsGetValue");
    return native != NULL ? native(index) : TlsGetValue(index);
}

THUNK(BOOL, FlsSetValue, 8, (DWORD index, void *data))
{
    typedef BOOL (WINAPI *fls_fn)(DWORD, void *);
    fls_fn native = (fls_fn)GetProcAddress(GetModuleHandleA("kernel32.dll"), "FlsSetValue");
    return native != NULL ? native(index, data) : TlsSetValue(index, data);
}

/* Windows NT 4 only offers a process exception filter, which runs later
   in dispatch than a vectored exception handler. */
THUNK(void *, AddVectoredExceptionHandler, 8, (ULONG first, LPTOP_LEVEL_EXCEPTION_FILTER handler))
{
    SetUnhandledExceptionFilter(handler);
    return (void *)handler;
}

THUNK(void, RtlCaptureContext, 4, (CONTEXT *context))
{
    /* The Native AOT x86 caller uses only CS and SS. */
    unsigned short cs, ss;
    __asm__ ("mov %%cs, %0" : "=r"(cs));
    __asm__ ("mov %%ss, %0" : "=r"(ss));
    context->SegCs = cs;
    context->SegSs = ss;
}

THUNK(BOOL, CopyContext, 12, (CONTEXT *to, DWORD flags, CONTEXT *from))
{
    *to = *from;
    to->ContextFlags = flags;
    return TRUE;
}

THUNK(BOOL, InitializeContext, 16, (void *buffer, DWORD flags, CONTEXT **context, DWORD *size))
{
    if (!buffer || *size < sizeof(CONTEXT)) {
        *size = sizeof(CONTEXT);
        SetLastError(ERROR_INSUFFICIENT_BUFFER);
        return FALSE;
    }
    *context = (CONTEXT *)buffer;
    memset(*context, 0, sizeof(**context));
    (*context)->ContextFlags = flags;
    return TRUE;
}

THUNK(DWORD64, GetEnabledXStateFeatures, 0, (void))
{
    return 0;
}

THUNK(BOOL, SetXStateFeaturesMask, 12, (CONTEXT *context, DWORD64 features))
{
    if (features == 0) {
        return TRUE;
    }
    SetLastError(ERROR_NOT_SUPPORTED);
    return FALSE;
}

THUNK(HANDLE, CreateMemoryResourceNotification, 4, (int type))
{
    SetLastError(ERROR_NOT_SUPPORTED);
    return NULL;
}

THUNK(BOOL, GetModuleHandleExW, 12, (DWORD flags, const WCHAR *name, HMODULE *module))
{
    *module = NULL;
    if (!(flags & GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT)) {
        SetLastError(ERROR_NOT_SUPPORTED);
        return FALSE;
    }
    if (flags & GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS) {
        MEMORY_BASIC_INFORMATION info;
        if (!VirtualQuery(name, &info, sizeof(info)) || info.Type != MEM_IMAGE) {
            SetLastError(ERROR_MOD_NOT_FOUND);
            return FALSE;
        }
        *module = (HMODULE)info.AllocationBase;
    } else {
        *module = GetModuleHandleW(name);
    }
    return *module != NULL;
}

THUNK(BOOL, GetLogicalProcessorInformation, 8, (void *info, DWORD *size))
{
    SetLastError(ERROR_NOT_SUPPORTED);
    return FALSE;
}

THUNK(SIZE_T, GetLargePageMinimum, 0, (void))
{
    return 0;
}

THUNK(WORD, GetMaximumProcessorGroupCount, 0, (void))
{
    return 1;
}

THUNK(BOOL, GetNumaHighestNodeNumber, 4, (ULONG *node))
{
    *node = 0;
    return TRUE;
}

THUNK(void *, VirtualAllocExNuma, 24, (HANDLE process, void *address, SIZE_T size, DWORD type, DWORD protection, DWORD node))
{
    return VirtualAllocEx(process, address, size, type, protection);
}

THUNK(BOOL, IsProcessInJob, 12, (HANDLE process, HANDLE job, BOOL *in_job))
{
    if (process != GetCurrentProcess() || job != NULL) {
        SetLastError(ERROR_NOT_SUPPORTED);
        return FALSE;
    }
    JOBOBJECT_BASIC_ACCOUNTING_INFORMATION accounting;
    *in_job = QueryInformationJobObject(NULL, JobObjectBasicAccountingInformation, &accounting, sizeof(accounting), NULL);
    return TRUE;
}

THUNK(BOOL, K32GetProcessMemoryInfo, 12, (HANDLE process, PROCESS_MEMORY_COUNTERS *counters, DWORD size))
{
    return GetProcessMemoryInfo(process, counters, size);
}

THUNK(BOOL, QueryUnbiasedInterruptTime, 4, (ULONGLONG *time))
{
    /* Windows NT 4 falls back to the uptime clock, with its 32-bit wrap. */
    *time = (ULONGLONG)GetTickCount() * 10000;
    return TRUE;
}

THUNK(void, RaiseFailFastException, 12, (EXCEPTION_RECORD *record, CONTEXT *context, DWORD flags))
{
    TerminateProcess(GetCurrentProcess(), record ? record->ExceptionCode : (DWORD)0xc0000409);
}

THUNK(void, FlushProcessWriteBuffers, 0, (void))
{
    /* Change protection on a locked page to force a TLB
       shootdown. Abort if the OS cannot provide that barrier. */
    static volatile LONG busy;
    static void *page;
    while (InterlockedExchange(&busy, 1)) {
        Sleep(0);
    }
    if (page == NULL) {
        page = VirtualAlloc(NULL, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (page == NULL || !VirtualLock(page, 4096)) {
            TerminateProcess(GetCurrentProcess(), 1);
        }
    }
    DWORD old;
    if (!VirtualProtect(page, 4096, PAGE_READONLY, &old) ||
        !VirtualProtect(page, 4096, PAGE_READWRITE, &old)) {
        TerminateProcess(GetCurrentProcess(), 1);
    }
    InterlockedExchange(&busy, 0);
}

THUNK(void, GetNativeSystemInfo, 4, (SYSTEM_INFO *info))
{
    GetSystemInfo(info);
}


typedef HANDLE (WINAPI *open_wait_handle_fn)(DWORD access, BOOL inherit, const WCHAR *name);

static HANDLE open_existing_wait_handle(HANDLE handle, const WCHAR *name, SECURITY_ATTRIBUTES *security,
    DWORD access, open_wait_handle_fn open_handle)
{
    if (handle != NULL || name == NULL || GetLastError() != ERROR_ACCESS_DENIED) {
        return handle;
    }

    /* The legacy create call asks for all access to an existing object.
       Retry the open with the caller's rights if the object's ACL denied it. */
    handle = open_handle(access, security != NULL && security->bInheritHandle, name);
    if (handle != NULL) {
        SetLastError(ERROR_ALREADY_EXISTS);
    }
    return handle;
}

THUNK(HANDLE, CreateEventExW, 16, (SECURITY_ATTRIBUTES *security, const WCHAR *name, DWORD flags, DWORD access))
{
    typedef HANDLE (WINAPI *create_event_fn)(SECURITY_ATTRIBUTES *, const WCHAR *, DWORD, DWORD);
    HMODULE kernel = GetModuleHandleA("kernel32.dll");
    create_event_fn native = (create_event_fn)GetProcAddress(kernel, "CreateEventExW");
    if (native != NULL) {
        return native(security, name, flags, access);
    }
    if (flags & ~3u) {
        SetLastError(ERROR_INVALID_PARAMETER);
        return NULL;
    }

    HANDLE handle = CreateEventW(security, flags & 1, flags & 2, name);
    return open_existing_wait_handle(handle, name, security, access, OpenEventW);
}

THUNK(HANDLE, CreateMutexExW, 16, (SECURITY_ATTRIBUTES *security, const WCHAR *name, DWORD flags, DWORD access))
{
    typedef HANDLE (WINAPI *create_mutex_fn)(SECURITY_ATTRIBUTES *, const WCHAR *, DWORD, DWORD);
    HMODULE kernel = GetModuleHandleA("kernel32.dll");
    create_mutex_fn native = (create_mutex_fn)GetProcAddress(kernel, "CreateMutexExW");
    if (native != NULL) {
        return native(security, name, flags, access);
    }
    if ((flags & ~CREATE_MUTEX_INITIAL_OWNER) != 0) {
        SetLastError(ERROR_INVALID_PARAMETER);
        return NULL;
    }
    if (access != MUTEX_ALL_ACCESS && access != (MAXIMUM_ALLOWED | SYNCHRONIZE | MUTEX_MODIFY_STATE)) {
        SetLastError(ERROR_NOT_SUPPORTED);
        return NULL;
    }

    HANDLE handle = CreateMutexW(security, (flags & CREATE_MUTEX_INITIAL_OWNER) != 0, name);
    return open_existing_wait_handle(handle, name, security, access, OpenMutexW);
}

THUNK(HANDLE, CreateSemaphoreExW, 24, (SECURITY_ATTRIBUTES *security, LONG initial, LONG maximum,
    const WCHAR *name, DWORD flags, DWORD access))
{
    typedef HANDLE (WINAPI *create_semaphore_fn)(SECURITY_ATTRIBUTES *, LONG, LONG, const WCHAR *, DWORD, DWORD);
    HMODULE kernel = GetModuleHandleA("kernel32.dll");
    create_semaphore_fn native = (create_semaphore_fn)GetProcAddress(kernel, "CreateSemaphoreExW");
    if (native != NULL) {
        return native(security, initial, maximum, name, flags, access);
    }
    if (flags != 0) {
        SetLastError(ERROR_INVALID_PARAMETER);
        return NULL;
    }
    if (access != SEMAPHORE_ALL_ACCESS && access != (MAXIMUM_ALLOWED | SYNCHRONIZE | SEMAPHORE_MODIFY_STATE)) {
        SetLastError(ERROR_NOT_SUPPORTED);
        return NULL;
    }

    HANDLE handle = CreateSemaphoreW(security, initial, maximum, name);
    return open_existing_wait_handle(handle, name, security, access, OpenSemaphoreW);
}

THUNK(BOOL, WaitOnAddress, 16, (const volatile BYTE *address, const BYTE *comparison, SIZE_T size, DWORD timeout))
{
    if (size != 1 && size != 2 && size != 4 && size != 8) {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    for (SIZE_T i = 0; i < size; ++i) {
        if (address[i] != comparison[i]) {
            return TRUE;
        }
    }
    if (!timeout) {
        SetLastError(ERROR_TIMEOUT);
        return FALSE;
    }
    /* WaitOnAddress allows spurious wakes. The caller rechecks its state. */
    Sleep(1);
    return TRUE;
}

THUNK(void, WakeByAddressSingle, 4, (void *address))
{
}

THUNK(HRESULT, CoGetApartmentType, 8, (int *type, int *qualifier))
{
    /* NT 4.0 has CoInitializeEx but no apartment query. A balanced MTA
       initialization distinguishes an existing MTA from an uninitialized thread. */
    HRESULT hr = CoInitializeEx(NULL, COINIT_MULTITHREADED);
    if (hr == RPC_E_CHANGED_MODE) {
        *type = 0; /* APTTYPE_STA */
    } else if (SUCCEEDED(hr)) {
        CoUninitialize();
        if (hr == S_OK) {
            return CO_E_NOTINITIALIZED;
        }
        *type = 1; /* APTTYPE_MTA */
    } else {
        return hr;
    }
    *qualifier = 0;
    return S_OK;
}

static BOOL same_module_path(const wchar_t *left, const wchar_t *right)
{
    typedef BOOLEAN (NTAPI *equal_unicode_fn)(const UNICODE_STRING *, const UNICODE_STRING *, BOOLEAN);
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    equal_unicode_fn equal = (equal_unicode_fn)GetProcAddress(ntdll, "RtlEqualUnicodeString");
    USHORT left_bytes = (USHORT)(lstrlenW(left) * sizeof(wchar_t));
    USHORT right_bytes = (USHORT)(lstrlenW(right) * sizeof(wchar_t));
    UNICODE_STRING a = {left_bytes, left_bytes, (wchar_t *)left};
    UNICODE_STRING b = {right_bytes, right_bytes, (wchar_t *)right};
    return equal != NULL && equal(&a, &b, TRUE);
}

static BOOL is_process_import(const wchar_t *name)
{
    /* NTDLL is loaded by the NT process loader itself. */
    if (same_module_path(name, L"ntdll.dll")) {
        return TRUE;
    }

    const BYTE *image = (const BYTE *)GetModuleHandleW(NULL);
    const IMAGE_DOS_HEADER *dos = (const IMAGE_DOS_HEADER *)image;
    const IMAGE_NT_HEADERS *pe = (const IMAGE_NT_HEADERS *)(image + dos->e_lfanew);
    const IMAGE_DATA_DIRECTORY *directory = &pe->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (directory->VirtualAddress == 0) {
        return FALSE;
    }

    const IMAGE_IMPORT_DESCRIPTOR *imports = (const IMAGE_IMPORT_DESCRIPTOR *)(image + directory->VirtualAddress);
    for (DWORD i = 0; i < directory->Size / sizeof(*imports) && imports[i].Name != 0; ++i) {
        wchar_t imported[MAX_PATH];
        if (MultiByteToWideChar(CP_ACP, 0, (const char *)image + imports[i].Name, -1, imported, MAX_PATH) &&
            same_module_path(name, imported)) {
            return TRUE;
        }
    }
    return FALSE;
}

static BOOL resident_system_library_path(const wchar_t *name, wchar_t *path)
{
    /* Work only with a leaf name. The verified import keeps its module resident. */
    if (name == NULL) {
        return FALSE;
    }
    UINT length = 0;
    BOOL has_extension = FALSE;
    for (; length < MAX_PATH && name[length] != L'\0'; ++length) {
        wchar_t ch = name[length];
        if (ch == L'\\' || ch == L'/' || ch == L':') {
            return FALSE;
        }
        has_extension |= ch == L'.';
    }

    const UINT extension_length = has_extension ? 0 : 4;
    UINT prefix = GetSystemDirectoryW(path, MAX_PATH);
    if (length == 0 || prefix == 0 || prefix >= MAX_PATH ||
        length + extension_length + 2 > MAX_PATH - prefix) {
        return FALSE;
    }
    path[prefix++] = L'\\';
    wchar_t *leaf = path + prefix;
    memcpy(leaf, name, length * sizeof(wchar_t));
    if (!has_extension) {
        memcpy(leaf + length, L".dll", extension_length * sizeof(wchar_t));
    }
    leaf[length + extension_length] = L'\0';

    if (!is_process_import(leaf)) {
        return FALSE;
    }
    HMODULE module = GetModuleHandleW(leaf);
    wchar_t loaded_path[MAX_PATH];
    DWORD loaded_length = module == NULL ? 0 : GetModuleFileNameW(module, loaded_path, MAX_PATH);
    if (loaded_length == 0 || loaded_length >= MAX_PATH || !same_module_path(loaded_path, path)) {
        return FALSE;
    }
    memcpy(path, loaded_path, (loaded_length + 1) * sizeof(wchar_t));
    return TRUE;
}

THUNK(HMODULE, LoadLibraryExW, 12, (const wchar_t *name, HANDLE file, DWORD flags))
{
    typedef HMODULE (WINAPI *load_library_fn)(const wchar_t *, HANDLE, DWORD);
    HMODULE kernel = GetModuleHandleW(L"kernel32.dll");
    load_library_fn load_library = (load_library_fn)GetProcAddress(kernel, "LoadLibraryExW");
    if ((flags & ~0xffu) && GetProcAddress(kernel, "AddDllDirectory") == NULL) {
        wchar_t path[MAX_PATH];
        if (flags == LOAD_LIBRARY_SEARCH_SYSTEM32 && file == NULL && resident_system_library_path(name, path)) {
            /* Take a reference to the already loaded system module. This starts no dependency search. */
            return load_library(path, NULL, 0);
        }
        /* ERROR_INVALID_PARAMETER would trigger a retry using the classic search order. */
        SetLastError(ERROR_NOT_SUPPORTED);
        return NULL;
    }
    return load_library(name, file, flags);
}

THUNK(BOOL, SetThreadErrorMode, 8, (DWORD mode, DWORD *previous))
{
    typedef BOOL (WINAPI *set_thread_error_mode_fn)(DWORD, DWORD *);
    HMODULE kernel = GetModuleHandleW(L"kernel32.dll");
    set_thread_error_mode_fn native = (set_thread_error_mode_fn)GetProcAddress(kernel, "SetThreadErrorMode");
    if (native != NULL) {
        return native(mode, previous);
    }

    /* Only the loader and filesystem's critical-error flag is needed here. */
    if (mode & ~SEM_FAILCRITICALERRORS) {
        SetLastError(ERROR_NOT_SUPPORTED);
        return FALSE;
    }

    const DWORD rtl_fail_critical_errors = 0x10;
    DWORD requested = mode ? rtl_fail_critical_errors : 0;
    DWORD old_mode;

    DWORD version = GetVersion();
    BYTE major = LOBYTE(LOWORD(version));
    if ((version & 0x80000000u) || (major != 4 && major != 5)) {
        SetLastError(ERROR_NOT_SUPPORTED);
        return FALSE;
    }

    /* NT 4 and NT 5 x86 store HardErrorsAreDisabled at TEB offset 0xf28.
       Update only the per-thread bit used for loader and media dialogs. */
    DWORD *hard_error_mode = (DWORD *)((char *)NtCurrentTeb() + 0xf28);
    old_mode = *hard_error_mode;
    *hard_error_mode = (old_mode & ~rtl_fail_critical_errors) | requested;

    if (previous != NULL) {
        *previous = (old_mode & rtl_fail_critical_errors) ? SEM_FAILCRITICALERRORS : 0;
    }
    return TRUE;
}

THUNK(BOOL, SetFileInformationByHandle, 16, (HANDLE file, FILE_INFO_BY_HANDLE_CLASS type, void *info, DWORD size))
{
    typedef BOOL (WINAPI *set_file_info_fn)(HANDLE, FILE_INFO_BY_HANDLE_CLASS, void *, DWORD);
    HMODULE kernel = GetModuleHandleA("kernel32.dll");
    set_file_info_fn native = (set_file_info_fn)GetProcAddress(kernel, "SetFileInformationByHandle");
    if (native != NULL) {
        return native(file, type, info, size);
    }

    /* NT already supports these information classes without moving the file pointer. */
    FILE_INFORMATION_CLASS nt_type;
    if (type == FileEndOfFileInfo) {
        nt_type = FileEndOfFileInformation;
    } else if (type == FileAllocationInfo && size >= sizeof(FILE_ALLOCATION_INFO)) {
        nt_type = FileAllocationInformation;
    } else if (type == FileBasicInfo) {
        nt_type = FileBasicInformation;
    } else {
        SetLastError(ERROR_NOT_SUPPORTED);
        return FALSE;
    }

    typedef NTSTATUS (NTAPI *nt_set_info_fn)(HANDLE, IO_STATUS_BLOCK *, void *, ULONG, FILE_INFORMATION_CLASS);
    typedef ULONG (NTAPI *nt_status_error_fn)(NTSTATUS);
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    nt_set_info_fn set_info = (nt_set_info_fn)GetProcAddress(ntdll, "NtSetInformationFile");
    nt_status_error_fn status_error = (nt_status_error_fn)GetProcAddress(ntdll, "RtlNtStatusToDosError");
    IO_STATUS_BLOCK status_block;
    NTSTATUS status = set_info(file, &status_block, info, size, nt_type);
    if (status < 0) {
        SetLastError(status_error(status));
        return FALSE;
    }
    return TRUE;
}

THUNK(BOOL, CreateHardLinkW, 12, (const wchar_t *link, const wchar_t *target, SECURITY_ATTRIBUTES *security))
{
    typedef BOOL (WINAPI *create_link_fn)(const wchar_t *, const wchar_t *, SECURITY_ATTRIBUTES *);
    HMODULE kernel = GetModuleHandleA("kernel32.dll");
    create_link_fn native = (create_link_fn)GetProcAddress(kernel, "CreateHardLinkW");
    if (native != NULL) {
        return native(link, target, security);
    }
    if (link == NULL || target == NULL || security != NULL) {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    /* NT 4 supports NTFS hard links through the native file-link information class. */
    typedef BOOLEAN (NTAPI *dos_path_fn)(const wchar_t *, UNICODE_STRING *, wchar_t **, void *);
    typedef void (NTAPI *free_unicode_fn)(UNICODE_STRING *);
    typedef NTSTATUS (NTAPI *set_info_fn)(HANDLE, IO_STATUS_BLOCK *, void *, ULONG, FILE_INFORMATION_CLASS);
    typedef ULONG (NTAPI *status_error_fn)(NTSTATUS);
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    dos_path_fn nt_path = (dos_path_fn)GetProcAddress(ntdll, "RtlDosPathNameToNtPathName_U");
    free_unicode_fn free_unicode = (free_unicode_fn)GetProcAddress(ntdll, "RtlFreeUnicodeString");
    set_info_fn set_info = (set_info_fn)GetProcAddress(ntdll, "NtSetInformationFile");
    status_error_fn status_error = (status_error_fn)GetProcAddress(ntdll, "RtlNtStatusToDosError");

    UNICODE_STRING name;
    if (!nt_path(link, &name, NULL, NULL)) {
        SetLastError(ERROR_INVALID_NAME);
        return FALSE;
    }

    struct {
        BOOLEAN replace;
        HANDLE root;
        ULONG name_bytes;
        wchar_t name[1];
    } *info;
    HANDLE heap = GetProcessHeap();
    ULONG size = sizeof(*info) + name.Length;
    info = HeapAlloc(heap, HEAP_ZERO_MEMORY, size);
    if (info == NULL) {
        free_unicode(&name);
        SetLastError(ERROR_NOT_ENOUGH_MEMORY);
        return FALSE;
    }
    info->name_bytes = name.Length;
    memcpy(info->name, name.Buffer, name.Length);
    free_unicode(&name);

    HANDLE file = CreateFileW(target, 0, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    DWORD error;
    if (file == INVALID_HANDLE_VALUE) {
        error = GetLastError();
    } else {
        IO_STATUS_BLOCK status_block;
        NTSTATUS status = set_info(file, &status_block, info, size, FileLinkInformation);
        error = status < 0 ? status_error(status) : ERROR_SUCCESS;
        CloseHandle(file);
    }
    HeapFree(heap, 0, info);
    if (error != ERROR_SUCCESS) {
        SetLastError(error);
        return FALSE;
    }
    return TRUE;
}

THUNK(HANDLE, FindFirstFileExW, 24, (const wchar_t *name, FINDEX_INFO_LEVELS level, void *data,
    FINDEX_SEARCH_OPS search, void *filter, DWORD flags))
{
    typedef HANDLE (WINAPI *find_first_fn)(const wchar_t *, FINDEX_INFO_LEVELS, void *, FINDEX_SEARCH_OPS, void *, DWORD);
    find_first_fn native = (find_first_fn)GetProcAddress(GetModuleHandleA("kernel32.dll"), "FindFirstFileExW");
    HANDLE handle = native(name, level, data, search, filter, flags);
    if (handle == INVALID_HANDLE_VALUE && level == FindExInfoBasic && GetLastError() == ERROR_INVALID_PARAMETER) {
        // The basic info level was introduced after NT 4 and Windows 2000.
        return native(name, FindExInfoStandard, data, search, filter, flags);
    }
    return handle;
}

THUNK(DWORD, GetDynamicTimeZoneInformation, 4, (DYNAMIC_TIME_ZONE_INFORMATION *info))
{
    typedef DWORD (WINAPI *dynamic_time_zone_fn)(DYNAMIC_TIME_ZONE_INFORMATION *);
    DYNAMIC_TIME_ZONE_INFORMATION empty = {0};
    TIME_ZONE_INFORMATION legacy;
    DWORD id;
    dynamic_time_zone_fn native = (dynamic_time_zone_fn)GetProcAddress(GetModuleHandleA("kernel32.dll"), "GetDynamicTimeZoneInformation");
    if (native != NULL) {
        return native(info);
    }

    /* Older Windows provides the current rules, without a time-zone key name. */
    id = GetTimeZoneInformation(&legacy);
    if (id != TIME_ZONE_ID_INVALID) {
        *info = empty;
        memcpy(info, &legacy, sizeof(legacy));
    }
    return id;
}

THUNK(BOOL, GetFileInformationByHandleEx, 16, (HANDLE file, FILE_INFO_BY_HANDLE_CLASS type, void *info, DWORD size))
{
    if (type == FileStandardInfo && size >= sizeof(FILE_STANDARD_INFO)) {
        BY_HANDLE_FILE_INFORMATION legacy;
        if (!GetFileInformationByHandle(file, &legacy)) {
            return FALSE;
        }
        FILE_STANDARD_INFO *standard = info;
        standard->EndOfFile.HighPart = legacy.nFileSizeHigh;
        standard->EndOfFile.LowPart = legacy.nFileSizeLow;
        standard->AllocationSize = standard->EndOfFile;
        standard->NumberOfLinks = legacy.nNumberOfLinks;
        standard->DeletePending = FALSE;
        standard->Directory = !!(legacy.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY);
        return TRUE;
    }
    if (type == FileAttributeTagInfo && size >= sizeof(FILE_ATTRIBUTE_TAG_INFO)) {
        BY_HANDLE_FILE_INFORMATION legacy;
        if (!GetFileInformationByHandle(file, &legacy)) {
            return FALSE;
        }
        FILE_ATTRIBUTE_TAG_INFO *attributes = info;
        attributes->FileAttributes = legacy.dwFileAttributes;
        attributes->ReparseTag = 0;
        return TRUE;
    }
    SetLastError(ERROR_NOT_SUPPORTED);
    return FALSE;
}

THUNK(BOOL, GetSystemTimes, 12, (FILETIME *idle, FILETIME *kernel, FILETIME *user))
{
    SetLastError(ERROR_NOT_SUPPORTED);
    return FALSE;
}

THUNK(BOOL, GetThreadIOPendingFlag, 8, (HANDLE thread, BOOL *pending))
{
    /* The portable pool may keep the worker rather than retire it when
       the OS lacks a safe way to check its pending I/O. */
    *pending = TRUE;
    return TRUE;
}

THUNK(HANDLE, OpenThread, 12, (DWORD access, BOOL inherit, DWORD thread_id))
{
    typedef HANDLE (WINAPI *open_thread_fn)(DWORD, BOOL, DWORD);
    HMODULE kernel = GetModuleHandleA("kernel32.dll");
    open_thread_fn native = (open_thread_fn)GetProcAddress(kernel, "OpenThread");
    if (native != NULL) {
        return native(access, inherit, thread_id);
    }

    /* NT 4 exposes NtOpenThread. A null process ID selects the thread by ID alone. */
    typedef NTSTATUS (NTAPI *nt_open_thread_fn)(HANDLE *, ACCESS_MASK, OBJECT_ATTRIBUTES *, CLIENT_ID *);
    typedef ULONG (NTAPI *nt_status_error_fn)(NTSTATUS);
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    nt_open_thread_fn open_thread = (nt_open_thread_fn)GetProcAddress(ntdll, "NtOpenThread");
    nt_status_error_fn status_error = (nt_status_error_fn)GetProcAddress(ntdll, "RtlNtStatusToDosError");

    OBJECT_ATTRIBUTES attributes = {0};
    attributes.Length = sizeof(attributes);
    attributes.Attributes = inherit ? OBJ_INHERIT : 0;
    CLIENT_ID client = {NULL, (HANDLE)(ULONG_PTR)thread_id};
    HANDLE handle = NULL;
    NTSTATUS status = open_thread(&handle, access, &attributes, &client);
    if (status < 0) {
        SetLastError(status_error(status));
        return NULL;
    }
    return handle;
}

THUNK(BOOL, GetQueuedCompletionStatusEx, 24, (HANDLE port, OVERLAPPED_ENTRY *entries, ULONG count,
    ULONG *removed, DWORD wait, BOOL alertable))
{
    *removed = 0;
    if (count == 0 || alertable) {
        SetLastError(ERROR_NOT_SUPPORTED);
        return FALSE;
    }
    DWORD transferred;
    ULONG_PTR key;
    OVERLAPPED *overlapped;
    BOOL ok = GetQueuedCompletionStatus(port, &transferred, &key, &overlapped, wait);
    if (!ok && overlapped == NULL) {
        return FALSE;
    }
    entries->lpCompletionKey = key;
    entries->lpOverlapped = overlapped;
    entries->Internal = overlapped ? overlapped->Internal : 0;
    entries->dwNumberOfBytesTransferred = transferred;
    *removed = 1;
    return TRUE;
}

THUNK(BOOL, QueryInformationJobObject, 20, (HANDLE job, JOBOBJECTINFOCLASS kind, void *output, DWORD capacity, DWORD *length))
{
    /* Job objects were introduced in NT 5.0. */
    SetLastError(ERROR_NOT_SUPPORTED);
    return FALSE;
}

THUNK(BOOL, HeapQueryInformation, 20, (HANDLE heap, HEAP_INFORMATION_CLASS type, void *info, SIZE_T size, SIZE_T *required))
{
    SetLastError(ERROR_NOT_SUPPORTED);
    return FALSE;
}

THUNK(BOOL, GlobalMemoryStatusEx, 4, (MEMORYSTATUSEX *memory))
{
    if (memory->dwLength != sizeof(*memory)) {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    MEMORYSTATUS legacy;
    legacy.dwLength = sizeof(legacy);
    GlobalMemoryStatus(&legacy);
    memory->dwMemoryLoad = legacy.dwMemoryLoad;
    memory->ullTotalPhys = legacy.dwTotalPhys;
    memory->ullAvailPhys = legacy.dwAvailPhys;
    memory->ullTotalPageFile = legacy.dwTotalPageFile;
    memory->ullAvailPageFile = legacy.dwAvailPageFile;
    memory->ullTotalVirtual = legacy.dwTotalVirtual;
    memory->ullAvailVirtual = legacy.dwAvailVirtual;
    memory->ullAvailExtendedVirtual = 0;
    return TRUE;
}

THUNK(void *, VirtualAlloc, 16, (void *address, SIZE_T size, DWORD type, DWORD protect))
{
    /* The GC tests MEM_WRITE_WATCH by trying VirtualAlloc. Reject it even
       when a newer host supports it because this profile cannot track writes. */
    if (type & MEM_WRITE_WATCH) {
        SetLastError(ERROR_NOT_SUPPORTED);
        return NULL;
    }
    /* NT 4 has VirtualAllocEx. Windows 95 OSR2.1 does not export it. */
    return VirtualAllocEx(GetCurrentProcess(), address, size, type, protect);
}

THUNK(UINT, GetWriteWatch, 24, (DWORD flags, void *address, SIZE_T size, void **pages, ULONG_PTR *count, ULONG *page_size))
{
    return ERROR_NOT_SUPPORTED;
}

THUNK(UINT, ResetWriteWatch, 8, (void *address, SIZE_T size))
{
    return ERROR_NOT_SUPPORTED;
}

THUNK(BOOL, GetFileSizeEx, 8, (HANDLE file, LARGE_INTEGER *size))
{
    typedef BOOL (WINAPI *get_file_size_ex_fn)(HANDLE, LARGE_INTEGER *);
    get_file_size_ex_fn native = (get_file_size_ex_fn)GetProcAddress(GetModuleHandleA("kernel32.dll"), "GetFileSizeEx");
    if (native != NULL) {
        return native(file, size);
    }

    /* NT 4 lacks GetFileSizeEx, including CRT imports from native libraries. */
    DWORD high;
    SetLastError(NO_ERROR);
    DWORD low = GetFileSize(file, &high);
    if (low == INVALID_FILE_SIZE && GetLastError() != NO_ERROR) {
        return FALSE;
    }
    size->QuadPart = ((ULONGLONG)high << 32) | low;
    return TRUE;
}

THUNK(BOOL, SetFilePointerEx, 20, (HANDLE file, LARGE_INTEGER distance, LARGE_INTEGER *position, DWORD origin))
{
    SetLastError(NO_ERROR);
    DWORD offset = SetFilePointer(file, distance.LowPart, &distance.HighPart, origin);
    if (offset == INVALID_SET_FILE_POINTER && GetLastError() != NO_ERROR) {
        return FALSE;
    }
    if (position != NULL) {
        position->LowPart = offset;
        position->HighPart = distance.HighPart;
    }
    return TRUE;
}

THUNK(BOOL, GetCPInfoExW, 12, (UINT codepage, DWORD flags, CPINFOEXW *info))
{
    CPINFO basic;
    if (flags != 0 || !GetCPInfo(codepage, &basic)) {
        return FALSE;
    }
    if (codepage == CP_ACP) {
        codepage = GetACP();
    }
    else if (codepage == CP_OEMCP) {
        codepage = GetOEMCP();
    }

    memset(info, 0, sizeof(*info));
    info->MaxCharSize = basic.MaxCharSize;
    info->CodePage = codepage;
    memcpy(info->DefaultChar, basic.DefaultChar, sizeof(info->DefaultChar));
    memcpy(info->LeadByte, basic.LeadByte, sizeof(info->LeadByte));
    MultiByteToWideChar(codepage, 0, (const char *)basic.DefaultChar, basic.DefaultChar[1] ? 2 : 1,
        &info->UnicodeDefaultChar, 1);
    return TRUE;
}

THUNK(HRESULT, CoWaitForMultipleHandles, 20, (DWORD flags, DWORD timeout, ULONG count, HANDLE *handles, DWORD *index))
{
    /* For the initial console profile, NT 4 supports a kernel wait.
       This does not pump COM calls on an STA. */
    DWORD result = WaitForMultipleObjectsEx(count, handles, !!(flags & COWAIT_WAITALL), timeout, !!(flags & COWAIT_ALERTABLE));
    if (result == WAIT_FAILED) {
        return HRESULT_FROM_WIN32(GetLastError());
    }
    if (result == WAIT_TIMEOUT) {
        return RPC_S_CALLPENDING;
    }
    *index = result;
    return S_OK;
}

/* This object registers no x86 SEH handlers. */
__asm__(".def @feat.00; .scl 3; .type 0; .endef\n.set @feat.00, 1");

typedef int (WSAAPI *close_socket_fn)(SOCKET);

static SOCKET clear_socket_inheritance(SOCKET socket, close_socket_fn close_socket)
{
    if (socket != INVALID_SOCKET && !SetHandleInformation((HANDLE)socket, HANDLE_FLAG_INHERIT, 0)) {
        DWORD error = GetLastError();
        close_socket(socket);
        SetLastError(error);
        return INVALID_SOCKET;
    }
    return socket;
}

THUNK(SOCKET, WSASocketW, 24, (int family, int type, int protocol, WSAPROTOCOL_INFOW *info, GROUP group, DWORD flags))
{
    typedef SOCKET (WSAAPI *socket_fn)(int, int, int, WSAPROTOCOL_INFOW *, GROUP, DWORD);
    HMODULE winsock = GetModuleHandleA("ws2_32.dll");
    socket_fn native = (socket_fn)GetProcAddress(winsock, "WSASocketW");
    if (native == NULL) {
        SetLastError(WSAEOPNOTSUPP);
        return INVALID_SOCKET;
    }
    if ((GetVersion() & 0x800000ffu) != 4 || !(flags & WSA_FLAG_NO_HANDLE_INHERIT)) {
        return native(family, type, protocol, info, group, flags);
    }

    /* NT 4 can succeed with an unknown flag without clearing inheritance. */
    close_socket_fn close_socket = (close_socket_fn)GetProcAddress(winsock, "closesocket");
    if (close_socket == NULL) {
        SetLastError(WSAEOPNOTSUPP);
        return INVALID_SOCKET;
    }
    SOCKET socket = native(family, type, protocol, info, group, flags & ~WSA_FLAG_NO_HANDLE_INHERIT);
    return clear_socket_inheritance(socket, close_socket);
}

THUNK(SOCKET, accept, 12, (SOCKET listen_socket, struct sockaddr *address, int *length))
{
    typedef SOCKET (WSAAPI *accept_fn)(SOCKET, struct sockaddr *, int *);
    HMODULE winsock = GetModuleHandleA("ws2_32.dll");
    accept_fn native = (accept_fn)GetProcAddress(winsock, "accept");
    if (native == NULL) {
        SetLastError(WSAEOPNOTSUPP);
        return INVALID_SOCKET;
    }
    if ((GetVersion() & 0x800000ffu) != 4) {
        return native(listen_socket, address, length);
    }

    /* Old NT can return an inheritable socket even for a non-inheritable listener. */
    close_socket_fn close_socket = (close_socket_fn)GetProcAddress(winsock, "closesocket");
    if (close_socket == NULL) {
        SetLastError(WSAEOPNOTSUPP);
        return INVALID_SOCKET;
    }
    SOCKET socket = native(listen_socket, address, length);
    return clear_socket_inheritance(socket, close_socket);
}
