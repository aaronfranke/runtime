// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <windows.h>
#include <winternl.h>
#include <objbase.h>
#include <wincrypt.h>
#include <ntsecapi.h>
#include <psapi.h>
#include <string.h>

#if defined(_WIN64)
#define COFF_NAME(name, bytes) #name
#else
#define COFF_NAME(name, bytes) "_" #name "@" #bytes
#endif

/* Resolve both direct calls and import references to the compatibility functions. */
#define THUNK(ret, name, bytes, args) \
    ret WINAPI compat_##name args __asm__(COFF_NAME(name, bytes)); \
    ret (WINAPI *const iat_##name) args __asm__("__imp_" COFF_NAME(name, bytes)) = compat_##name; \
    ret WINAPI compat_##name args

#include "WinNtConsole.inc"

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
    if (native == NULL) {
        return (LONG)0xc0000001;
    }

    LONG status = native(version);
    /* Windows 2000's RtlGetVersion leaves the service-pack text empty. */
    if (status == 0 && version->dwMajorVersion == 5 && version->dwMinorVersion == 0 &&
        version->szCSDVersion[0] == L'\0') {
        OSVERSIONINFOW legacy = {0};
        legacy.dwOSVersionInfoSize = sizeof(legacy);
        if (GetVersionExW(&legacy)) {
            memcpy(version->szCSDVersion, legacy.szCSDVersion, sizeof(legacy.szCSDVersion));
        }
    }
    return status;
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

#if !defined(_WIN64)
/* NT 5.0/5.1 expose RtlEncryptMemory/RtlDecryptMemory with the same protection
   modes as the newer Crypt32 exports, but with an 8-byte block size.
   NT 4 does not provide these native memory-protection functions. */
static BOOL protect_memory(void *data, DWORD length, DWORD flags, BOOL encrypt)
{
    if ((length & 15u) != 0) {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    if (flags > 2) {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    NTSTATUS status = encrypt ? RtlEncryptMemory(data, length, flags) : RtlDecryptMemory(data, length, flags);
    if (status < 0) {
        SetLastError(RtlNtStatusToDosError(status));
        return FALSE;
    }
    return TRUE;
}

THUNK(BOOL, CryptProtectMemory, 12, (void *data, DWORD length, DWORD flags))
{
    return protect_memory(data, length, flags, TRUE);
}

THUNK(BOOL, CryptUnprotectMemory, 12, (void *data, DWORD length, DWORD flags))
{
    return protect_memory(data, length, flags, FALSE);
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
#endif

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

#if !defined(_WIN64)
THUNK(void, InitializeSListHead, 4, (SLIST_HEADER *header))
{
    memset(header, 0, sizeof(*header));
}

/* Use FLS when the host exports it. Windows 2000 has only TLS,
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

/* Windows 2000 only offers a process exception filter, which runs later
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
#endif

#if defined(_WIN64)
#define WINNT5_REQUIRE_NATIVE_DLL_SEARCH
#include "WinLegacySystemCompat.inc"
#else
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
#endif

#if !defined(_WIN64)
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
#endif

#if defined(_WIN64)
THUNK(BOOL, GetProcessGroupAffinity, 12, (HANDLE process, USHORT *count, USHORT *groups))
{
    typedef BOOL (WINAPI *get_group_affinity_fn)(HANDLE, USHORT *, USHORT *);
    get_group_affinity_fn get_affinity = (get_group_affinity_fn)kernel_proc("GetProcessGroupAffinity");
    if (get_affinity != NULL) {
        return get_affinity(process, count, groups);
    }

    /* The GC defaults to one processor group when this API is unavailable. */
    SetLastError(ERROR_CALL_NOT_IMPLEMENTED);
    return FALSE;
}

THUNK(BOOL, GetLogicalProcessorInformationEx, 12, (LOGICAL_PROCESSOR_RELATIONSHIP relationship,
    SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX *information, DWORD *length))
{
    typedef BOOL (WINAPI *get_processor_info_fn)(LOGICAL_PROCESSOR_RELATIONSHIP,
        SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX *, DWORD *);
    get_processor_info_fn get_information = (get_processor_info_fn)kernel_proc("GetLogicalProcessorInformationEx");
    if (get_information != NULL) {
        return get_information(relationship, information, length);
    }
    SetLastError(ERROR_CALL_NOT_IMPLEMENTED);
    return FALSE;
}
#endif

THUNK(WORD, GetMaximumProcessorGroupCount, 0, (void))
{
#if defined(_WIN64)
    typedef WORD (WINAPI *get_group_count_fn)(void);
    get_group_count_fn get_count = (get_group_count_fn)kernel_proc("GetMaximumProcessorGroupCount");
    if (get_count != NULL) {
        return get_count();
    }
#endif
    return 1;
}

#if !defined(_WIN64)
THUNK(BOOL, GetNumaHighestNodeNumber, 4, (ULONG *node))
{
    *node = 0;
    return TRUE;
}
#endif

THUNK(void *, VirtualAllocExNuma, 24, (HANDLE process, void *address, SIZE_T size, DWORD type, DWORD protection, DWORD node))
{
    return VirtualAllocEx(process, address, size, type, protection);
}

#if !defined(_WIN64)
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
#endif

THUNK(BOOL, K32GetProcessMemoryInfo, 12, (HANDLE process, PROCESS_MEMORY_COUNTERS *counters, DWORD size))
{
    return GetProcessMemoryInfo(process, counters, size);
}

THUNK(BOOL, QueryUnbiasedInterruptTime, 4, (ULONGLONG *time))
{
    /* Windows 2000 falls back to the uptime clock, with its 32-bit wrap. */
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

#if !defined(_WIN64)
THUNK(void, GetNativeSystemInfo, 4, (SYSTEM_INFO *info))
{
    GetSystemInfo(info);
}
#endif


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
    /* NT 5.0 has CoInitializeEx but no apartment query. A balanced MTA
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
/* This object registers no x86 SEH handlers. */
#if !defined(_WIN64)
__asm__(".def @feat.00; .scl 3; .type 0; .endef\n.set @feat.00, 1");
#endif

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

THUNK(HMODULE, LoadLibraryExW, 12, (LPCWSTR name, HANDLE file, DWORD flags))
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

#if defined(_WIN64)
    /* XP Professional x64 Edition provides the native thread error mode API. */
    typedef DWORD (WINAPI *get_rtl_error_mode_fn)(void);
    typedef LONG (WINAPI *set_rtl_error_mode_fn)(DWORD, DWORD *);
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    get_rtl_error_mode_fn get_mode = (get_rtl_error_mode_fn)GetProcAddress(ntdll, "RtlGetThreadErrorMode");
    set_rtl_error_mode_fn set_mode = (set_rtl_error_mode_fn)GetProcAddress(ntdll, "RtlSetThreadErrorMode");
    if (get_mode == NULL || set_mode == NULL) {
        SetLastError(ERROR_NOT_SUPPORTED);
        return FALSE;
    }
    old_mode = get_mode();
    /* XP x64 returns BOOL here. Check the resulting mode to also support
       native implementations that return NTSTATUS. */
    set_mode((old_mode & ~rtl_fail_critical_errors) | requested, NULL);
    if ((get_mode() & rtl_fail_critical_errors) != requested) {
        SetLastError(ERROR_NOT_SUPPORTED);
        return FALSE;
    }
#else
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
#endif

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

typedef BOOLEAN (NTAPI *prefix_unicode_fn)(const UNICODE_STRING *, const UNICODE_STRING *, BOOLEAN);

static DWORD write_dos_file_path(const UNICODE_STRING *name, wchar_t *path, DWORD capacity, prefix_unicode_fn prefix)
{
    DWORD name_length = name->Length / sizeof(wchar_t);
    DWORD drives = GetLogicalDrives();
    wchar_t drive[] = L"A:";
    for (; drives != 0; drives >>= 1, ++drive[0]) {
        wchar_t mapping[1024];
        if (!(drives & 1) || !QueryDosDeviceW(drive, mapping, sizeof(mapping) / sizeof(mapping[0]))) {
            continue;
        }

        DWORD device_length = lstrlenW(mapping);
        USHORT device_bytes = (USHORT)(device_length * sizeof(wchar_t));
        UNICODE_STRING device = {device_bytes, device_bytes, mapping};
        if (!prefix(&device, name, TRUE) ||
            (device_length < name_length && name->Buffer[device_length] != L'\\')) {
            continue;
        }

        DWORD suffix_length = name_length - device_length;
        DWORD length = 6 + (suffix_length != 0 ? suffix_length : 1);
        if (capacity <= length) {
            return length + 1;
        }

        memcpy(path, L"\\\\?\\", 4 * sizeof(wchar_t));
        path[4] = drive[0];
        path[5] = L':';
        if (suffix_length != 0) {
            memcpy(path + 6, name->Buffer + device_length, suffix_length * sizeof(wchar_t));
        } else {
            path[6] = L'\\';
        }
        path[length] = 0;
        return length;
    }
    return 0;
}

THUNK(DWORD, GetFinalPathNameByHandleW, 16, (HANDLE file, wchar_t *path, DWORD capacity, DWORD flags))
{
    typedef DWORD (WINAPI *final_path_fn)(HANDLE, wchar_t *, DWORD, DWORD);
    HMODULE kernel = GetModuleHandleA("kernel32.dll");
    final_path_fn native = (final_path_fn)GetProcAddress(kernel, "GetFinalPathNameByHandleW");
    if (native != NULL) {
        return native(file, path, capacity, flags);
    }

    /* The NT 5 fallback implements the normalized DOS path used for junctions. */
    if (flags != (FILE_NAME_NORMALIZED | VOLUME_NAME_DOS)) {
        SetLastError(ERROR_NOT_SUPPORTED);
        return 0;
    }

    typedef NTSTATUS (NTAPI *query_object_fn)(HANDLE, OBJECT_INFORMATION_CLASS, void *, ULONG, ULONG *);
    typedef ULONG (NTAPI *nt_status_error_fn)(NTSTATUS);
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    query_object_fn query = (query_object_fn)GetProcAddress(ntdll, "NtQueryObject");
    nt_status_error_fn status_error = (nt_status_error_fn)GetProcAddress(ntdll, "RtlNtStatusToDosError");
    prefix_unicode_fn prefix = (prefix_unicode_fn)GetProcAddress(ntdll, "RtlPrefixUnicodeString");

    /* NT 5 returns the canonical NTFS name through ObjectNameInformation,
       including when the open traversed junctions in parent components. */
    union {
        UNICODE_STRING name;
        wchar_t buffer[MAX_PATH + 32];
    } local_name;
    UNICODE_STRING *name = &local_name.name;
    ULONG bytes = 0;
    NTSTATUS status = query(file, ObjectNameInformation, name, sizeof(local_name), &bytes);
    HANDLE heap = NULL;
    if (status < 0 && bytes > sizeof(local_name)) {
        heap = GetProcessHeap();
        name = HeapAlloc(heap, 0, bytes);
        if (name == NULL) {
            SetLastError(ERROR_NOT_ENOUGH_MEMORY);
            return 0;
        }
        status = query(file, ObjectNameInformation, name, bytes, &bytes);
    }

    DWORD length = status < 0 ? 0 : write_dos_file_path(name, path, capacity, prefix);
    DWORD error = status < 0 ? status_error(status) : ERROR_PATH_NOT_FOUND;
    if (heap != NULL) {
        HeapFree(heap, 0, name);
    }
    if (length == 0) {
        SetLastError(error);
    }
    return length;
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

#if !defined(_WIN64)
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
#endif

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
    close_socket_fn close_socket = (close_socket_fn)GetProcAddress(winsock, "closesocket");

    if (native == NULL || close_socket == NULL) {
        SetLastError(ERROR_PROC_NOT_FOUND);
        return INVALID_SOCKET;
    }
    if ((GetVersion() & 0x800000ffu) != 5 || !(flags & WSA_FLAG_NO_HANDLE_INHERIT)) {
        return native(family, type, protocol, info, group, flags);
    }

    /* NT 5 predates WSA_FLAG_NO_HANDLE_INHERIT. */
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
    if ((GetVersion() & 0x800000ffu) > 5) {
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
