// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <windows.h>
#include <objbase.h>
#include <wincrypt.h>
#include <lmcons.h>
#include <psapi.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>
#include <tlhelp32.h>

#ifdef WIN95_NATIVE_AOT
#include "Win95Thread.h"
#endif

/* The x86 COFF aliases satisfy imported and direct stdcall
   references while using the unmodified MSVC-built runtime archives. */
#define THUNK(ret, name, bytes, args) \
    ret WINAPI compat_##name args __asm__("_" #name "@" #bytes); \
    ret (WINAPI *const iat_##name) args __asm__("__imp__" #name "@" #bytes) = compat_##name; \
    ret WINAPI compat_##name args

static BOOL is_win9x(void)
{
    return (GetVersion() & 0x80000000) != 0;
}

static FARPROC kernel_proc(const char *name)
{
    return GetProcAddress(GetModuleHandleA("KERNEL32.DLL"), name);
}

static BOOL ansi_string(const wchar_t *wide, char *ansi, int capacity)
{
    BOOL replaced = FALSE;
    int count = WideCharToMultiByte(CP_ACP, 0, wide, -1, ansi, capacity, NULL, &replaced);
    if (count != 0 && replaced) {
        SetLastError(ERROR_NO_UNICODE_TRANSLATION);
        return FALSE;
    }
    return count != 0;
}


static BOOL ansi_path(const wchar_t *wide, char *ansi, int capacity)
{
    /* The managed Windows library uses NT extended prefixes even for short paths. */
    if (wide[0] == L'\\' && wide[1] == L'\\' && wide[2] == L'?' && wide[3] == L'\\') {
        wide += 4;
        if ((wide[0] == L'U' || wide[0] == L'u') && (wide[1] == L'N' || wide[1] == L'n') &&
            (wide[2] == L'C' || wide[2] == L'c') && wide[3] == L'\\') {
            if (capacity <= 2) {
                SetLastError(ERROR_INSUFFICIENT_BUFFER);
                return FALSE;
            }
            ansi[0] = '\\';
            ansi[1] = '\\';
            return ansi_string(wide + 4, ansi + 2, capacity - 2);
        }

        BOOL drive = (wide[0] >= L'A' && wide[0] <= L'Z') || (wide[0] >= L'a' && wide[0] <= L'z');
        if (!drive || wide[1] != L':' || wide[2] != L'\\') {
            SetLastError(ERROR_INVALID_NAME);
            return FALSE;
        }
    }
    return ansi_string(wide, ansi, capacity);
}

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

THUNK(LONG, RtlGetVersion, 4, (OSVERSIONINFOW *version))
{
    if (!is_win9x()) {
        typedef LONG (WINAPI *get_version_fn)(OSVERSIONINFOW *);
        HMODULE ntdll = GetModuleHandleA("ntdll.dll");
        get_version_fn native = (get_version_fn)GetProcAddress(ntdll, "RtlGetVersion");
        if (native != NULL) {
            return native(version);
        }
    }

    /* Win9x supplies the base version structure through GetVersionExA. */
    if (version == NULL || version->dwOSVersionInfoSize != sizeof(*version)) {
        return (LONG)0xc000000d;
    }

    OSVERSIONINFOA legacy;
    legacy.dwOSVersionInfoSize = sizeof(legacy);
    if (!GetVersionExA(&legacy) ||
        !MultiByteToWideChar(CP_ACP, 0, legacy.szCSDVersion, -1,
            version->szCSDVersion, ARRAYSIZE(version->szCSDVersion))) {
        return (LONG)0xc0000001;
    }

    version->dwMajorVersion = legacy.dwMajorVersion;
    version->dwMinorVersion = legacy.dwMinorVersion;
    /* The Windows 95 and 98 build number occupies the low word. */
    version->dwBuildNumber = legacy.dwPlatformId == VER_PLATFORM_WIN32_WINDOWS ?
        LOWORD(legacy.dwBuildNumber) : legacy.dwBuildNumber;
    version->dwPlatformId = legacy.dwPlatformId;
    return 0;
}

static BOOL random_bytes(BYTE *bytes, DWORD length)
{
    HCRYPTPROV provider;
    if (!CryptAcquireContextA(&provider, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT))
        return FALSE;
    BOOL result = CryptGenRandom(provider, length, bytes);
    CryptReleaseContext(provider, 0);
    return result;
}

THUNK(HRESULT, CoCreateGuid, 4, (GUID *guid))
{
    if (!is_win9x()) {
        typedef HRESULT (WINAPI *create_guid_fn)(GUID *);
        HMODULE ole32 = GetModuleHandleA("OLE32.DLL");
        create_guid_fn native = (create_guid_fn)GetProcAddress(ole32, "CoCreateGuid");
        return native != NULL ? native(guid) : E_NOTIMPL;
    }

    /* Win95 OLE returns time-based GUIDs. Native AOT also uses NewGuid
       to supply the random bits of UUIDv7. */
    if (guid == NULL) {
        return E_INVALIDARG;
    }
    if (!random_bytes((BYTE *)guid, sizeof(*guid))) {
        return E_FAIL;
    }
    guid->Data3 = (guid->Data3 & 0x0fff) | 0x4000;
    guid->Data4[0] = (guid->Data4[0] & 0x3f) | 0x80;
    return S_OK;
}

THUNK(LONG, BCryptGenRandom, 16, (void *algorithm, BYTE *bytes, ULONG length, ULONG flags))
{
    if (algorithm != NULL || flags != 2)
        return (LONG)0xc000000d;
    return random_bytes(bytes, length) ? 0 : (LONG)0xc0000001;
}

static volatile LONG pointer_cookie;

static ULONG_PTR cookie(void)
{
    LONG value = pointer_cookie;
    if (value == 0) {
        if (!random_bytes((BYTE *)&value, sizeof(value)))
            TerminateProcess(GetCurrentProcess(), 1);
        if (!value)
            value = 1;
        LONG previous = InterlockedCompareExchange(&pointer_cookie, value, 0);
        if (previous)
            value = previous;
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

THUNK(BOOL, InitializeCriticalSectionEx, 12, (CRITICAL_SECTION *section, DWORD count, DWORD flags))
{
    InitializeCriticalSection(section);
    return TRUE;
}

THUNK(void, InitializeSListHead, 4, (SLIST_HEADER *header))
{
    memset(header, 0, sizeof(*header));
}

/* Use FLS when the host exports it. Windows 9x has only TLS,
   which does not deliver thread or fiber destruction callbacks. */
THUNK(DWORD, FlsAlloc, 4, (PFLS_CALLBACK_FUNCTION callback))
{
    typedef DWORD (WINAPI *fls_fn)(PFLS_CALLBACK_FUNCTION);
    fls_fn native = (fls_fn)kernel_proc("FlsAlloc");
    return native != NULL ? native(callback) : TlsAlloc();
}

THUNK(BOOL, FlsFree, 4, (DWORD index))
{
    typedef BOOL (WINAPI *fls_fn)(DWORD);
    fls_fn native = (fls_fn)kernel_proc("FlsFree");
    return native != NULL ? native(index) : TlsFree(index);
}

THUNK(void *, FlsGetValue, 4, (DWORD index))
{
    typedef void * (WINAPI *fls_fn)(DWORD);
    fls_fn native = (fls_fn)kernel_proc("FlsGetValue");
    return native != NULL ? native(index) : TlsGetValue(index);
}

THUNK(BOOL, FlsSetValue, 8, (DWORD index, void *data))
{
    typedef BOOL (WINAPI *fls_fn)(DWORD, void *);
    fls_fn native = (fls_fn)kernel_proc("FlsSetValue");
    return native != NULL ? native(index, data) : TlsSetValue(index, data);
}

/* Windows 9x only offers a process exception filter, which runs later
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
    if (features == 0)
        return TRUE;
    SetLastError(ERROR_NOT_SUPPORTED);
    return FALSE;
}

THUNK(HANDLE, CreateMemoryResourceNotification, 4, (int type))
{
    SetLastError(ERROR_NOT_SUPPORTED);
    return NULL;
}

THUNK(HMODULE, GetModuleHandleW, 4, (const wchar_t *name))
{
    if (!is_win9x()) {
        typedef HMODULE (WINAPI *get_module_fn)(const wchar_t *);
        get_module_fn native = (get_module_fn)kernel_proc("GetModuleHandleW");
        return native(name);
    }
    if (name == NULL) {
        return GetModuleHandleA(NULL);
    }
    char ansi[MAX_PATH];
    if (!ansi_path(name, ansi, sizeof(ansi))) {
        return NULL;
    }
    return GetModuleHandleA(ansi);
}

THUNK(BOOL, GetModuleHandleExW, 12, (DWORD flags, const WCHAR *name, HMODULE *module))
{
    *module = NULL;
    if (!(flags & GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT)) {
        SetLastError(ERROR_NOT_SUPPORTED);
        return FALSE;
    }
    if (flags & GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS) {
        HMODULE exe = GetModuleHandleA(NULL);
        const IMAGE_DOS_HEADER *dos = (const IMAGE_DOS_HEADER *)exe;
        const IMAGE_NT_HEADERS32 *pe = (const IMAGE_NT_HEADERS32 *)((const char *)exe + dos->e_lfanew);
        ULONG_PTR offset = (ULONG_PTR)name - (ULONG_PTR)exe;
        if (offset >= pe->OptionalHeader.SizeOfImage) {
            SetLastError(ERROR_MOD_NOT_FOUND);
            return FALSE;
        }
        *module = exe;
    } else {
        char ansi[MAX_PATH * 2];
        if (name != NULL && !ansi_string(name, ansi, sizeof(ansi)))
            return FALSE;
        *module = GetModuleHandleA(name != NULL ? ansi : NULL);
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
    if (process != GetCurrentProcess()) {
        SetLastError(ERROR_NOT_SUPPORTED);
        return NULL;
    }
    return VirtualAlloc(address, size, type, protection);
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
    if (!is_win9x()) {
        typedef BOOL (WINAPI *memory_info_fn)(HANDLE, PROCESS_MEMORY_COUNTERS *, DWORD);
        memory_info_fn native = (memory_info_fn)kernel_proc("K32GetProcessMemoryInfo");
        if (native != NULL) {
            return native(process, counters, size);
        }
    }

    /* Windows 95 and 98 lack per-process PSAPI counters. */
    SetLastError(ERROR_NOT_SUPPORTED);
    return FALSE;
}

THUNK(BOOL, QueryUnbiasedInterruptTime, 4, (ULONGLONG *time))
{
    /* Windows 9x falls back to the uptime clock, with its 32-bit wrap. */
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
    while (InterlockedExchange(&busy, 1))
        Sleep(0);
    if (page == NULL) {
        page = VirtualAlloc(NULL, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (page == NULL || !VirtualLock(page, 4096))
            TerminateProcess(GetCurrentProcess(), 1);
    }
    DWORD old;
    if (!VirtualProtect(page, 4096, PAGE_READONLY, &old) ||
        !VirtualProtect(page, 4096, PAGE_READWRITE, &old))
        TerminateProcess(GetCurrentProcess(), 1);
    InterlockedExchange(&busy, 0);
}

THUNK(void, GetCurrentProcessorNumberEx, 4, (PROCESSOR_NUMBER *processor))
{
    if (!is_win9x()) {
        typedef void (WINAPI *get_processor_fn)(PROCESSOR_NUMBER *);
        get_processor_fn get_processor = (get_processor_fn)kernel_proc("GetCurrentProcessorNumberEx");
        if (get_processor != NULL) {
            get_processor(processor);
            return;
        }
    }

    /* Windows 9x schedules threads on a single logical processor. */
    *processor = (PROCESSOR_NUMBER){0};
}

THUNK(void, GetNativeSystemInfo, 4, (SYSTEM_INFO *info))
{
    GetSystemInfo(info);
}

THUNK(HANDLE, CreateEventExW, 16, (SECURITY_ATTRIBUTES *security, const WCHAR *name, DWORD flags, DWORD access))
{
    typedef HANDLE (WINAPI *create_event_fn)(SECURITY_ATTRIBUTES *, const WCHAR *, DWORD, DWORD);
    create_event_fn native = (create_event_fn)kernel_proc("CreateEventExW");
    if (native != NULL) {
        return native(security, name, flags, access);
    }
    if (flags & ~3u) {
        SetLastError(ERROR_INVALID_PARAMETER);
        return NULL;
    }
    return CreateEventW(security, flags & 1, flags & 2, name);
}

static HANDLE open_wait_handle(const char *wide, const char *ansi_export, DWORD access, BOOL inherit,
    const WCHAR *name)
{
    if (!is_win9x()) {
        typedef HANDLE (WINAPI *open_wait_fn)(DWORD, BOOL, const WCHAR *);
        open_wait_fn native = (open_wait_fn)kernel_proc(wide);
        if (native != NULL) {
            return native(access, inherit, name);
        }
    } else {
        typedef HANDLE (WINAPI *open_wait_ansi_fn)(DWORD, BOOL, const char *);
        open_wait_ansi_fn native = (open_wait_ansi_fn)kernel_proc(ansi_export);
        if (native != NULL) {
            char ansi[MAX_PATH * 2];
            if (name != NULL && !ansi_string(name, ansi, sizeof(ansi))) {
                return NULL;
            }
            return native(access, inherit, name != NULL ? ansi : NULL);
        }
    }
    SetLastError(ERROR_CALL_NOT_IMPLEMENTED);
    return NULL;
}

#define WIN9X_OPEN_WAIT_HANDLE(kind) \
THUNK(HANDLE, Open##kind##W, 12, (DWORD access, BOOL inherit, const WCHAR *name)) \
{ \
    return open_wait_handle("Open" #kind "W", "Open" #kind "A", access, inherit, name); \
}

WIN9X_OPEN_WAIT_HANDLE(Event)
WIN9X_OPEN_WAIT_HANDLE(Mutex)
WIN9X_OPEN_WAIT_HANDLE(Semaphore)

#undef WIN9X_OPEN_WAIT_HANDLE

THUNK(HANDLE, CreateFileMappingW, 24, (HANDLE file, SECURITY_ATTRIBUTES *security, DWORD protection,
    DWORD size_high, DWORD size_low, const WCHAR *name))
{
    /* Win9x exports CreateFileMappingW and OpenFileMappingW as stubs. */
    if (!is_win9x()) {
        typedef HANDLE (WINAPI *create_mapping_fn)(HANDLE, SECURITY_ATTRIBUTES *, DWORD, DWORD, DWORD, const WCHAR *);
        create_mapping_fn native = (create_mapping_fn)kernel_proc("CreateFileMappingW");
        return native(file, security, protection, size_high, size_low, name);
    }
    if (security != NULL && security->lpSecurityDescriptor != NULL) {
        SetLastError(ERROR_NOT_SUPPORTED);
        return NULL;
    }
    char ansi[MAX_PATH * 2];
    if (name != NULL && !ansi_string(name, ansi, sizeof(ansi))) {
        return NULL;
    }
    return CreateFileMappingA(file, security, protection, size_high, size_low, name != NULL ? ansi : NULL);
}

THUNK(HANDLE, OpenFileMappingW, 12, (DWORD access, BOOL inherit, const WCHAR *name))
{
    if (!is_win9x()) {
        typedef HANDLE (WINAPI *open_mapping_fn)(DWORD, BOOL, const WCHAR *);
        open_mapping_fn native = (open_mapping_fn)kernel_proc("OpenFileMappingW");
        return native(access, inherit, name);
    }
    char ansi[MAX_PATH * 2];
    if (name != NULL && !ansi_string(name, ansi, sizeof(ansi))) {
        return NULL;
    }
    HANDLE mapping = OpenFileMappingA(access, inherit, name != NULL ? ansi : NULL);
    if (mapping == NULL && GetLastError() == ERROR_INVALID_NAME) {
        /* Win9x uses ERROR_INVALID_NAME when the mapping name is absent. */
        SetLastError(ERROR_FILE_NOT_FOUND);
    }
    return mapping;
}

THUNK(HANDLE, CreateMutexExW, 16, (SECURITY_ATTRIBUTES *security, const WCHAR *name, DWORD flags, DWORD access))
{
    typedef HANDLE (WINAPI *create_mutex_fn)(SECURITY_ATTRIBUTES *, const WCHAR *, DWORD, DWORD);
    create_mutex_fn native = (create_mutex_fn)kernel_proc("CreateMutexExW");
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
    BOOL owned = (flags & CREATE_MUTEX_INITIAL_OWNER) != 0;
    if (!is_win9x()) {
        typedef HANDLE (WINAPI *legacy_mutex_fn)(SECURITY_ATTRIBUTES *, BOOL, const WCHAR *);
        legacy_mutex_fn legacy = (legacy_mutex_fn)kernel_proc("CreateMutexW");
        if (legacy == NULL) {
            SetLastError(ERROR_CALL_NOT_IMPLEMENTED);
            return NULL;
        }
        return legacy(security, owned, name);
    }
    if (security != NULL && security->lpSecurityDescriptor != NULL) {
        SetLastError(ERROR_NOT_SUPPORTED);
        return NULL;
    }
    char ansi[MAX_PATH * 2];
    if (name != NULL && !ansi_string(name, ansi, sizeof(ansi))) {
        return NULL;
    }
    return CreateMutexA(security, owned, name != NULL ? ansi : NULL);
}

THUNK(HANDLE, CreateSemaphoreExW, 24, (SECURITY_ATTRIBUTES *security, LONG initial, LONG maximum,
    const WCHAR *name, DWORD flags, DWORD access))
{
    typedef HANDLE (WINAPI *create_semaphore_fn)(SECURITY_ATTRIBUTES *, LONG, LONG, const WCHAR *, DWORD, DWORD);
    create_semaphore_fn native = (create_semaphore_fn)kernel_proc("CreateSemaphoreExW");
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
    if (!is_win9x()) {
        typedef HANDLE (WINAPI *legacy_semaphore_fn)(SECURITY_ATTRIBUTES *, LONG, LONG, const WCHAR *);
        legacy_semaphore_fn legacy = (legacy_semaphore_fn)kernel_proc("CreateSemaphoreW");
        if (legacy == NULL) {
            SetLastError(ERROR_CALL_NOT_IMPLEMENTED);
            return NULL;
        }
        return legacy(security, initial, maximum, name);
    }
    if (security != NULL && security->lpSecurityDescriptor != NULL) {
        SetLastError(ERROR_NOT_SUPPORTED);
        return NULL;
    }
    char ansi[MAX_PATH * 2];
    if (name != NULL && !ansi_string(name, ansi, sizeof(ansi))) {
        return NULL;
    }
    return CreateSemaphoreA(security, initial, maximum, name != NULL ? ansi : NULL);
}

THUNK(BOOL, WaitOnAddress, 16, (const volatile BYTE *address, const BYTE *comparison, SIZE_T size, DWORD timeout))
{
    if (size != 1 && size != 2 && size != 4 && size != 8) {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    for (SIZE_T i = 0; i < size; ++i)
        if (address[i] != comparison[i])
            return TRUE;
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
    /* Windows 98 has CoInitializeEx but no apartment query. A balanced MTA
       initialization distinguishes an existing MTA from an uninitialized thread. */
    int initialized_type = 1; /* APTTYPE_MTA */
    HRESULT hr = CoInitializeEx(NULL, COINIT_MULTITHREADED);
#ifdef WIN95_NATIVE_AOT
    if (hr == E_NOTIMPL) {
        /* STA-only OLE32 on Windows 95 returns S_FALSE for an existing STA. */
        hr = CoInitialize(NULL);
        if (FAILED(hr)) {
            return hr;
        }
        initialized_type = 0; /* APTTYPE_STA */
    }
#endif
    if (hr == RPC_E_CHANGED_MODE) {
        *type = 0; /* APTTYPE_STA */
    } else if (SUCCEEDED(hr)) {
        CoUninitialize();
        if (hr == S_OK) {
            return CO_E_NOTINITIALIZED;
        }
        *type = initialized_type;
    } else {
        return hr;
    }
    *qualifier = 0;
    return S_OK;
}

static BOOL is_process_import(const char *name)
{
    const BYTE *image = (const BYTE *)GetModuleHandleA(NULL);
    const IMAGE_DOS_HEADER *dos = (const IMAGE_DOS_HEADER *)image;
    const IMAGE_NT_HEADERS *pe = (const IMAGE_NT_HEADERS *)(image + dos->e_lfanew);
    const IMAGE_DATA_DIRECTORY *directory = &pe->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (directory->VirtualAddress == 0) {
        return FALSE;
    }

    const IMAGE_IMPORT_DESCRIPTOR *imports = (const IMAGE_IMPORT_DESCRIPTOR *)(image + directory->VirtualAddress);
    for (DWORD i = 0; i < directory->Size / sizeof(*imports) && imports[i].Name != 0; ++i) {
        if (lstrcmpiA(name, (const char *)image + imports[i].Name) == 0) {
            return TRUE;
        }
    }
    return FALSE;
}

static BOOL resident_system_library_path(const wchar_t *name, char *path)
{
    /* Accept ASCII leaf names only; do not let ANSI best-fit conversion select another DLL. */
    if (name == NULL) {
        return FALSE;
    }
    char leaf[MAX_PATH];
    UINT length = 0;
    BOOL has_extension = FALSE;
    for (; length < MAX_PATH && name[length] != L'\0'; ++length) {
        wchar_t ch = name[length];
        if (ch > 0x7f || ch == L'\\' || ch == L'/' || ch == L':') {
            return FALSE;
        }
        leaf[length] = (char)ch;
        has_extension |= ch == L'.';
    }
    UINT extension_length = has_extension ? 0 : 4;
    if (length == 0 || length + extension_length >= MAX_PATH) {
        return FALSE;
    }
    if (!has_extension) {
        memcpy(leaf + length, ".dll", extension_length);
    }
    leaf[length + extension_length] = '\0';

    /* A static process import remains loaded. This includes OLE32 on Native AOT;
       Windows 98 exports PropVariantClear, but Windows 95 does not. */
    if (!is_process_import(leaf)) {
        return FALSE;
    }
    HMODULE module = GetModuleHandleA(leaf);
    if (module == NULL) {
        return FALSE;
    }
    char expected[MAX_PATH];
    UINT system_length = GetSystemDirectoryA(expected, MAX_PATH);
    if (system_length == 0 || system_length >= MAX_PATH ||
        length + extension_length + 2 > MAX_PATH - system_length) {
        return FALSE;
    }
    expected[system_length++] = '\\';
    memcpy(expected + system_length, leaf, length + extension_length + 1);

    DWORD loaded_length = GetModuleFileNameA(module, path, MAX_PATH);
    return loaded_length != 0 && loaded_length < MAX_PATH && lstrcmpiA(path, expected) == 0;
}

THUNK(HMODULE, LoadLibraryExW, 12, (const wchar_t *name, HANDLE file, DWORD flags))
{
    if (!is_win9x()) {
        typedef HMODULE (WINAPI *load_library_fn)(const wchar_t *, HANDLE, DWORD);
        load_library_fn native = (load_library_fn)kernel_proc("LoadLibraryExW");
        return native(name, file, flags);
    }

    /* Win9x has only the classic search order, including for dependencies.
       ERROR_INVALID_PARAMETER would cause NativeLibrary to retry with default search. */
    const DWORD legacy_flags = DONT_RESOLVE_DLL_REFERENCES | LOAD_LIBRARY_AS_DATAFILE | LOAD_WITH_ALTERED_SEARCH_PATH;
    if (flags & ~legacy_flags) {
        char path[MAX_PATH];
        if (flags == LOAD_LIBRARY_SEARCH_SYSTEM32 && file == NULL && resident_system_library_path(name, path)) {
            /* Take a reference to the verified resident import; no dependency search starts. */
            return LoadLibraryExA(path, NULL, 0);
        }
        SetLastError(ERROR_NOT_SUPPORTED);
        return NULL;
    }
    if (name == NULL || file != NULL) {
        SetLastError(ERROR_INVALID_PARAMETER);
        return NULL;
    }
    char ansi[MAX_PATH];
    if (!ansi_path(name, ansi, sizeof(ansi))) {
        return NULL;
    }
    return LoadLibraryExA(ansi, NULL, flags);
}

THUNK(BOOL, SetThreadErrorMode, 8, (DWORD mode, DWORD *previous))
{
    typedef BOOL (WINAPI *set_thread_error_mode_fn)(DWORD, DWORD *);
    set_thread_error_mode_fn native = (set_thread_error_mode_fn)kernel_proc("SetThreadErrorMode");
    if (native != NULL) {
        return native(mode, previous);
    }

    /* Windows 9x can change the error mode only for the process. Do not
       change other threads' behavior when a caller requests a scoped mode. */
    SetLastError(ERROR_NOT_SUPPORTED);
    return FALSE;
}

THUNK(DWORD, GetDynamicTimeZoneInformation, 4, (DYNAMIC_TIME_ZONE_INFORMATION *info))
{
    typedef DWORD (WINAPI *dynamic_time_zone_fn)(DYNAMIC_TIME_ZONE_INFORMATION *);
    DYNAMIC_TIME_ZONE_INFORMATION empty = {0};
    TIME_ZONE_INFORMATION legacy;
    DWORD id;
    dynamic_time_zone_fn native = (dynamic_time_zone_fn)kernel_proc("GetDynamicTimeZoneInformation");
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
        if (!GetFileInformationByHandle(file, &legacy))
            return FALSE;
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
        if (!GetFileInformationByHandle(file, &legacy))
            return FALSE;
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

THUNK(BOOL, SetProcessAffinityMask, 8, (HANDLE process, DWORD_PTR mask))
{
    if (!is_win9x()) {
        typedef BOOL (WINAPI *set_affinity_fn)(HANDLE, DWORD_PTR);
        return ((set_affinity_fn)kernel_proc("SetProcessAffinityMask"))(process, mask);
    }

    /* Win95 lacks the setter and Win98 exports a stub. The affinity query
       still validates the process handle and reports both masks as 1. */
    DWORD_PTR process_mask, system_mask;
    if (!GetProcessAffinityMask(process, &process_mask, &system_mask)) {
        return FALSE;
    }
    if (process_mask != 1 || system_mask != 1) {
        SetLastError(ERROR_NOT_SUPPORTED);
        return FALSE;
    }
    if (mask != 1) {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    return TRUE;
}

THUNK(BOOL, GetThreadIOPendingFlag, 8, (HANDLE thread, BOOL *pending))
{
    /* The portable pool may keep the worker rather than retire it when
       the OS lacks a safe way to check its pending I/O. */
    *pending = TRUE;
    return TRUE;
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
    if (!ok && overlapped == NULL)
        return FALSE;
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
    typedef void *(WINAPI *allocate)(void *, SIZE_T, DWORD, DWORD);
    allocate native = (allocate)kernel_proc("VirtualAlloc");
    return native(address, size, type, protect);
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

    /* NT 4 and Win9x lack GetFileSizeEx, including CRT imports from native libraries. */
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
    if (offset == INVALID_SET_FILE_POINTER && GetLastError() != NO_ERROR)
        return FALSE;
    if (position != NULL) {
        position->LowPart = offset;
        position->HighPart = distance.HighPart;
    }
    return TRUE;
}

THUNK(BOOL, GetCPInfoExW, 12, (UINT codepage, DWORD flags, CPINFOEXW *info))
{
    CPINFO basic;
    if (flags != 0 || !GetCPInfo(codepage, &basic))
        return FALSE;
    if (codepage == CP_ACP)
        codepage = GetACP();
    else if (codepage == CP_OEMCP)
        codepage = GetOEMCP();

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
    /* For the initial console profile, Windows 9x supports a kernel wait.
       This does not pump COM calls on an STA. */
    DWORD result = WaitForMultipleObjectsEx(count, handles, !!(flags & COWAIT_WAITALL), timeout, !!(flags & COWAIT_ALERTABLE));
    if (result == WAIT_FAILED)
        return HRESULT_FROM_WIN32(GetLastError());
    if (result == WAIT_TIMEOUT)
        return RPC_S_CALLPENDING;
    *index = result;
    return S_OK;
}

THUNK(BOOL, InitializeCriticalSectionAndSpinCount, 8, (CRITICAL_SECTION *section, DWORD count))
{
    /* Windows 98 exports a stub and Windows 95 OSR2.1 lacks the export. */
    InitializeCriticalSection(section);
    return TRUE;
}

THUNK(wchar_t *, GetEnvironmentStringsW, 0, (void))
{
    if (!is_win9x()) {
        typedef wchar_t *(WINAPI *get_environment_fn)(void);
        return ((get_environment_fn)kernel_proc("GetEnvironmentStringsW"))();
    }

    char *block = GetEnvironmentStringsA();
    if (block == NULL)
        return NULL;

    const char *end = block;
    while (*end) {
        while (*end)
            ++end;
        ++end;
    }

    int length = end == block ? 2 : (int)(end - block) + 1;
    /* Win9x returns the environment block in its ANSI code page. */
    int count = MultiByteToWideChar(CP_ACP, 0, block, length, NULL, 0);
    HANDLE heap = GetProcessHeap();
    wchar_t *wide = count != 0 ? HeapAlloc(heap, 0, count * sizeof(wchar_t)) : NULL;
    DWORD error = count != 0 ? ERROR_NOT_ENOUGH_MEMORY : GetLastError();
    if (wide != NULL && MultiByteToWideChar(CP_ACP, 0, block, length, wide, count) != count) {
        error = GetLastError();
        HeapFree(heap, 0, wide);
        wide = NULL;
    }
    FreeEnvironmentStringsA(block);
    if (wide == NULL)
        SetLastError(error);
    return wide;
}

THUNK(BOOL, FreeEnvironmentStringsW, 4, (wchar_t *block))
{
    if (!is_win9x()) {
        typedef BOOL (WINAPI *free_environment_fn)(wchar_t *);
        return ((free_environment_fn)kernel_proc("FreeEnvironmentStringsW"))(block);
    }

    return HeapFree(GetProcessHeap(), 0, block);
}

THUNK(void, GetStartupInfoW, 4, (STARTUPINFOW *info))
{
    STARTUPINFOA ansi;
    GetStartupInfoA(&ansi);

    /* The CRT uses these fields to recover the inherited file handles. */
    *info = (STARTUPINFOW){0};
    info->cb = sizeof(*info);
    info->dwX = ansi.dwX;
    info->dwY = ansi.dwY;
    info->dwXSize = ansi.dwXSize;
    info->dwYSize = ansi.dwYSize;
    info->dwXCountChars = ansi.dwXCountChars;
    info->dwYCountChars = ansi.dwYCountChars;
    info->dwFillAttribute = ansi.dwFillAttribute;
    info->dwFlags = ansi.dwFlags;
    info->wShowWindow = ansi.wShowWindow;
    info->cbReserved2 = ansi.cbReserved2;
    info->lpReserved2 = ansi.lpReserved2;
    info->hStdInput = ansi.hStdInput;
    info->hStdOutput = ansi.hStdOutput;
    info->hStdError = ansi.hStdError;
}

THUNK(HANDLE, CreateEventW, 16, (SECURITY_ATTRIBUTES *security, BOOL manual, BOOL initial, const wchar_t *name))
{
    // Win9x cannot enforce a security descriptor on an event.
    if (is_win9x() && security != NULL && security->lpSecurityDescriptor != NULL) {
        SetLastError(ERROR_NOT_SUPPORTED);
        return NULL;
    }
    char ansi[MAX_PATH];
    if (name != NULL && !ansi_string(name, ansi, sizeof(ansi)))
        return NULL;
    return CreateEventA(security, manual, initial, name != NULL ? ansi : NULL);
}

THUNK(HANDLE, CreateThread, 24, (SECURITY_ATTRIBUTES *security, SIZE_T size, LPTHREAD_START_ROUTINE start,
    void *argument, DWORD flags, DWORD *id))
{
    typedef HANDLE (WINAPI *create_thread)(SECURITY_ATTRIBUTES *, SIZE_T, LPTHREAD_START_ROUTINE, void *, DWORD, DWORD *);
    create_thread native = (create_thread)kernel_proc("CreateThread");

    /* Win9x requires an output pointer even if the caller ignores the ID. */
    DWORD local_id;
#ifdef WIN95_NATIVE_AOT
    return Win95CreateThread(native, security, size, start, argument, flags, id != NULL ? id : &local_id);
#else
    return native(security, size, start, argument, flags, id != NULL ? id : &local_id);
#endif
}

THUNK(BOOL, SetFileAttributesW, 8, (const wchar_t *name, DWORD attributes))
{
    if (!is_win9x()) {
        typedef BOOL (WINAPI *set_attributes_fn)(const wchar_t *, DWORD);
        set_attributes_fn native = (set_attributes_fn)kernel_proc("SetFileAttributesW");
        return native(name, attributes);
    }
    char ansi[MAX_PATH * 2];
    return ansi_path(name, ansi, sizeof(ansi)) && SetFileAttributesA(ansi, attributes);
}

THUNK(BOOL, GetFileAttributesExW, 12, (const wchar_t *name, GET_FILEEX_INFO_LEVELS level, void *info))
{
    if (!is_win9x()) {
        typedef BOOL (WINAPI *get_attributes_fn)(const wchar_t *, GET_FILEEX_INFO_LEVELS, void *);
        get_attributes_fn native = (get_attributes_fn)kernel_proc("GetFileAttributesExW");
        return native(name, level, info);
    }
    char ansi[MAX_PATH * 2];
    if (!ansi_path(name, ansi, sizeof(ansi))) {
        return FALSE;
    }
    return GetFileAttributesExA(ansi, level, info);
}

static BOOL find_data_to_wide(const WIN32_FIND_DATAA *ansi, WIN32_FIND_DATAW *wide, BOOL alternate_name)
{
    memset(wide, 0, sizeof(*wide));
    wide->dwFileAttributes = ansi->dwFileAttributes;
    wide->ftCreationTime = ansi->ftCreationTime;
    wide->ftLastAccessTime = ansi->ftLastAccessTime;
    wide->ftLastWriteTime = ansi->ftLastWriteTime;
    wide->nFileSizeHigh = ansi->nFileSizeHigh;
    wide->nFileSizeLow = ansi->nFileSizeLow;
    return MultiByteToWideChar(CP_ACP, 0, ansi->cFileName, -1, wide->cFileName, MAX_PATH) != 0 &&
        (!alternate_name || MultiByteToWideChar(CP_ACP, 0, ansi->cAlternateFileName, -1, wide->cAlternateFileName, 14) != 0);
}

THUNK(HANDLE, FindFirstFileExW, 24, (const wchar_t *name, FINDEX_INFO_LEVELS info_level, void *output,
    FINDEX_SEARCH_OPS operation, void *filter, DWORD flags))
{
    if (!is_win9x()) {
        typedef HANDLE (WINAPI *find_first_fn)(const wchar_t *, FINDEX_INFO_LEVELS, void *, FINDEX_SEARCH_OPS, void *, DWORD);
        find_first_fn native = (find_first_fn)kernel_proc("FindFirstFileExW");
        return native(name, info_level, output, operation, filter, flags);
    }

    if ((info_level != FindExInfoStandard && info_level != FindExInfoBasic) ||
        operation != FindExSearchNameMatch || filter != NULL || flags != 0) {
        SetLastError(ERROR_NOT_SUPPORTED);
        return INVALID_HANDLE_VALUE;
    }

    char ansi[MAX_PATH * 2];
    if (!ansi_path(name, ansi, sizeof(ansi))) {
        return INVALID_HANDLE_VALUE;
    }

    WIN32_FIND_DATAA result;
    HANDLE find = FindFirstFileA(ansi, &result);
    if (find == INVALID_HANDLE_VALUE) {
        return find;
    }

    if (!find_data_to_wide(&result, output, info_level == FindExInfoStandard)) {
        DWORD error = GetLastError();
        FindClose(find);
        SetLastError(error);
        return INVALID_HANDLE_VALUE;
    }
    return find;
}

THUNK(BOOL, FindNextFileW, 8, (HANDLE find, WIN32_FIND_DATAW *output))
{
    if (!is_win9x()) {
        typedef BOOL (WINAPI *find_next_fn)(HANDLE, WIN32_FIND_DATAW *);
        find_next_fn native = (find_next_fn)kernel_proc("FindNextFileW");
        return native(find, output);
    }

    WIN32_FIND_DATAA result;
    return FindNextFileA(find, &result) && find_data_to_wide(&result, output, TRUE);
}

static BOOL copy_identity_w(const char *ansi, wchar_t *buffer, DWORD *size, BOOL count_terminator, DWORD short_buffer_error)
{
    int required = MultiByteToWideChar(CP_ACP, 0, ansi, -1, NULL, 0);
    if (required == 0) {
        return FALSE;
    }
    if (*size < (DWORD)required) {
        *size = (DWORD)required;
        SetLastError(short_buffer_error);
        return FALSE;
    }
    if (!MultiByteToWideChar(CP_ACP, 0, ansi, -1, buffer, required)) {
        return FALSE;
    }
    *size = count_terminator ? (DWORD)required : (DWORD)required - 1;
    return TRUE;
}

THUNK(BOOL, GetComputerNameW, 8, (wchar_t *buffer, DWORD *size))
{
    if (!is_win9x()) {
        typedef BOOL (WINAPI *get_name_fn)(wchar_t *, DWORD *);
        get_name_fn native = (get_name_fn)kernel_proc("GetComputerNameW");
        return native(buffer, size);
    }

    /* Win9x exposes the computer name through the ANSI API. */
    char ansi[(MAX_COMPUTERNAME_LENGTH + 1) * 2];
    DWORD length = sizeof(ansi);
    return GetComputerNameA(ansi, &length) &&
        copy_identity_w(ansi, buffer, size, FALSE, ERROR_BUFFER_OVERFLOW);
}

THUNK(BOOL, GetUserNameW, 8, (wchar_t *buffer, DWORD *size))
{
    if (!is_win9x()) {
        typedef BOOL (WINAPI *get_name_fn)(wchar_t *, DWORD *);
        HMODULE advapi = GetModuleHandleA("advapi32.dll");
        get_name_fn native = (get_name_fn)GetProcAddress(advapi, "GetUserNameW");
        return native(buffer, size);
    }

    /* The wide API is a stub on Win9x. GetUserNameA preserves the active logon name. */
    char ansi[(UNLEN + 1) * 2];
    DWORD length = sizeof(ansi);
    return GetUserNameA(ansi, &length) &&
        copy_identity_w(ansi, buffer, size, TRUE, ERROR_INSUFFICIENT_BUFFER);
}

THUNK(UINT, GetSystemDirectoryW, 8, (wchar_t *buffer, UINT capacity))
{
    if (!is_win9x()) {
        typedef UINT (WINAPI *get_system_directory_fn)(wchar_t *, UINT);
        get_system_directory_fn native = (get_system_directory_fn)kernel_proc("GetSystemDirectoryW");
        return native(buffer, capacity);
    }

    /* Win9x exports GetSystemDirectoryW as an unimplemented stub. */
    char ansi[MAX_PATH + 1];
    UINT length = GetSystemDirectoryA(ansi, sizeof(ansi));
    if (length == 0) {
        return 0;
    }
    if (length >= sizeof(ansi)) {
        SetLastError(ERROR_INSUFFICIENT_BUFFER);
        return 0;
    }

    int needed = MultiByteToWideChar(CP_ACP, 0, ansi, -1, NULL, 0);
    if (needed == 0 || (UINT)needed > capacity) {
        return needed;
    }
    int converted = MultiByteToWideChar(CP_ACP, 0, ansi, -1, buffer, needed);
    return converted == 0 ? 0 : converted - 1;
}

THUNK(DWORD, GetTempPathW, 8, (DWORD capacity, wchar_t *buffer))
{
    if (!is_win9x()) {
        typedef DWORD (WINAPI *get_temp_path_fn)(DWORD, wchar_t *);
        get_temp_path_fn native = (get_temp_path_fn)kernel_proc("GetTempPathW");
        return native(capacity, buffer);
    }
    char ansi[MAX_PATH + 1];
    DWORD length = GetTempPathA(sizeof(ansi), ansi);
    if (length == 0) {
        return 0;
    }
    if (length >= sizeof(ansi)) {
        SetLastError(ERROR_INSUFFICIENT_BUFFER);
        return 0;
    }
    int needed = MultiByteToWideChar(CP_ACP, 0, ansi, -1, NULL, 0);
    if (needed == 0 || (DWORD)needed > capacity) {
        return needed;
    }
    int written = MultiByteToWideChar(CP_ACP, 0, ansi, -1, buffer, needed);
    return written != 0 ? written - 1 : 0;
}

THUNK(DWORD, GetModuleFileNameW, 12, (HMODULE module, wchar_t *buffer, DWORD capacity))
{
    if (!is_win9x()) {
        typedef DWORD (WINAPI *get_module_file_name_fn)(HMODULE, wchar_t *, DWORD);
        get_module_file_name_fn native = (get_module_file_name_fn)kernel_proc("GetModuleFileNameW");
        return native(module, buffer, capacity);
    }
    if (capacity == 0) {
        SetLastError(ERROR_INSUFFICIENT_BUFFER);
        return 0;
    }

    char ansi[MAX_PATH];
    DWORD length = GetModuleFileNameA(module, ansi, sizeof(ansi));
    if (length == 0) {
        return 0;
    }
    if (length >= sizeof(ansi)) {
        SetLastError(ERROR_FILENAME_EXCED_RANGE);
        return 0;
    }
    wchar_t wide[MAX_PATH];
    int converted = MultiByteToWideChar(CP_ACP, 0, ansi, length, wide, MAX_PATH);
    if (converted == 0) {
        return 0;
    }
    if ((DWORD)converted >= capacity) {
        memcpy(buffer, wide, (capacity - 1) * sizeof(wchar_t));
        buffer[capacity - 1] = L'\0';
        SetLastError(ERROR_INSUFFICIENT_BUFFER);
        return capacity;
    }
    memcpy(buffer, wide, converted * sizeof(wchar_t));
    buffer[converted] = L'\0';
    return (DWORD)converted;
}

THUNK(DWORD, GetFullPathNameW, 16, (const wchar_t *name, DWORD capacity, wchar_t *buffer, wchar_t **part))
{
    char ansi[MAX_PATH * 2], full[MAX_PATH * 2], *file = NULL;
    if (!ansi_path(name, ansi, sizeof(ansi))) {
        return 0;
    }

    DWORD length = GetFullPathNameA(ansi, sizeof(full), full, part != NULL ? &file : NULL);
    if (length == 0)
        return 0;
    if (length >= sizeof(full)) {
        SetLastError(ERROR_FILENAME_EXCED_RANGE);
        return 0;
    }

    int required = MultiByteToWideChar(CP_ACP, 0, full, -1, NULL, 0);
    if (required == 0 || (DWORD)required > capacity)
        return required;
    if (!MultiByteToWideChar(CP_ACP, 0, full, -1, buffer, required))
        return 0;

    if (part != NULL) {
        *part = NULL;
        if (file != NULL) {
            int prefix = file == full ? 0 : MultiByteToWideChar(CP_ACP, 0, full, file - full, NULL, 0);
            *part = buffer + prefix;
        }
    }
    return required - 1;
}

THUNK(HANDLE, CreateFileW, 28, (const wchar_t *name, DWORD access, DWORD share, SECURITY_ATTRIBUTES *security,
    DWORD creation, DWORD flags, HANDLE template_file))
{
    if (!is_win9x()) {
        typedef HANDLE (WINAPI *create_file)(const wchar_t *, DWORD, DWORD, SECURITY_ATTRIBUTES *, DWORD, DWORD, HANDLE);
        create_file native = (create_file)kernel_proc("CreateFileW");
        return native(name, access, share, security, creation, flags, template_file);
    }

    char ansi[MAX_PATH * 2];
    if (!ansi_path(name, ansi, sizeof(ansi))) {
        return INVALID_HANDLE_VALUE;
    }

    /* Win9x has no NT security QoS or reparse points, and needs generic
       write access to open a file for timestamp updates. */
    flags &= ~(SECURITY_VALID_SQOS_FLAGS | FILE_FLAG_OPEN_REPARSE_POINT);
    if (access == FILE_WRITE_ATTRIBUTES) {
        access = GENERIC_WRITE;
    }
    // Win9x cannot grant delete sharing on an open handle.
    share &= ~FILE_SHARE_DELETE;
    return CreateFileA(ansi, access, share, security, creation, flags, template_file);
}

static BOOL seek_file(HANDLE file, LONG low, LONG *high, DWORD origin, DWORD *position)
{
    SetLastError(NO_ERROR);
    *position = SetFilePointer(file, low, high, origin);
    return *position != INVALID_SET_FILE_POINTER || GetLastError() == NO_ERROR;
}

typedef BOOL (WINAPI *read_file_fn)(HANDLE, void *, DWORD, DWORD *, OVERLAPPED *);
typedef BOOL (WINAPI *write_file_fn)(HANDLE, const void *, DWORD, DWORD *, OVERLAPPED *);

typedef enum { POSITION_READ, POSITION_WRITE, POSITION_TRUNCATE } position_operation;

/* Serialize Win9x operations that temporarily reposition an open file. */
static BOOL file_io_at_offset(position_operation mode, FARPROC operation, HANDLE file, const void *buffer,
    DWORD bytes, DWORD *transferred, LONG offset_low, LONG offset_high)
{
    static volatile LONG positioning;
    while (InterlockedExchange(&positioning, 1)) {
        Sleep(0);
    }

    LONG original_high = 0;
    DWORD original_low, unused;
    BOOL result = FALSE;
    if (seek_file(file, 0, &original_high, FILE_CURRENT, &original_low) &&
        seek_file(file, offset_low, &offset_high, FILE_BEGIN, &unused)) {
        if (mode == POSITION_TRUNCATE) {
            result = SetEndOfFile(file);
        } else if (mode == POSITION_WRITE) {
            result = ((write_file_fn)operation)(file, buffer, bytes, transferred, NULL);
        } else {
            result = ((read_file_fn)operation)(file, (void *)buffer, bytes, transferred, NULL);
        }
        DWORD error = GetLastError();
        if (seek_file(file, (LONG)original_low, &original_high, FILE_BEGIN, &unused)) {
            SetLastError(error);
        } else {
            result = FALSE;
        }
    }

    DWORD error = GetLastError();
    InterlockedExchange(&positioning, 0);
    SetLastError(error);
    return result;
}

THUNK(BOOL, SetFileInformationByHandle, 16, (HANDLE file, FILE_INFO_BY_HANDLE_CLASS type, void *info, DWORD size))
{
    if (!is_win9x()) {
        typedef BOOL (WINAPI *set_file_info_fn)(HANDLE, FILE_INFO_BY_HANDLE_CLASS, void *, DWORD);
        set_file_info_fn native = (set_file_info_fn)kernel_proc("SetFileInformationByHandle");
        return native(file, type, info, size);
    }

    if (type == FileEndOfFileInfo && size >= sizeof(FILE_END_OF_FILE_INFO)) {
        const FILE_END_OF_FILE_INFO *end = info;
        return file_io_at_offset(POSITION_TRUNCATE, NULL, file, NULL, 0, NULL,
            (LONG)end->EndOfFile.LowPart, end->EndOfFile.HighPart);
    }
    if (type == FileBasicInfo && size >= sizeof(FILE_BASIC_INFO)) {
        const FILE_BASIC_INFO *basic = info;
        if (basic->ChangeTime.QuadPart == 0 && basic->FileAttributes == 0) {
            FILETIME creation = {basic->CreationTime.LowPart, (DWORD)basic->CreationTime.HighPart};
            FILETIME access = {basic->LastAccessTime.LowPart, (DWORD)basic->LastAccessTime.HighPart};
            FILETIME write = {basic->LastWriteTime.LowPart, (DWORD)basic->LastWriteTime.HighPart};
            return SetFileTime(file, basic->CreationTime.QuadPart != 0 ? &creation : NULL,
                basic->LastAccessTime.QuadPart != 0 ? &access : NULL,
                basic->LastWriteTime.QuadPart != 0 ? &write : NULL);
        }
    }
    SetLastError(ERROR_NOT_SUPPORTED);
    return FALSE;
}

THUNK(BOOL, ReadFile, 20, (HANDLE file, void *buffer, DWORD bytes, DWORD *read, OVERLAPPED *overlapped))
{
    read_file_fn native = (read_file_fn)kernel_proc("ReadFile");
    if (!is_win9x() || overlapped == NULL || overlapped->hEvent != NULL || read == NULL) {
        return native(file, buffer, bytes, read, overlapped);
    }

    /* Win9x requires NULL for the synchronous pipe I/O used by RandomAccess. */
    DWORD file_type = GetFileType(file);
    if (file_type == FILE_TYPE_PIPE) {
        return native(file, buffer, bytes, read, NULL);
    }
    if (file_type != FILE_TYPE_DISK) {
        return native(file, buffer, bytes, read, overlapped);
    }

    return file_io_at_offset(POSITION_READ, (FARPROC)native, file, buffer, bytes, read,
        (LONG)overlapped->Offset, (LONG)overlapped->OffsetHigh);
}

#include "Win9xConsole.inc"

THUNK(BOOL, WriteFile, 20, (HANDLE file, const void *buffer, DWORD bytes, DWORD *written, OVERLAPPED *overlapped))
{
    write_file_fn native = (write_file_fn)kernel_proc("WriteFile");

    if (overlapped == NULL && written != NULL && file == GetStdHandle(STD_OUTPUT_HANDLE) && is_win9x()) {
        BOOL handled;
        BOOL result = terminal_write(file, buffer, bytes, written, &handled);
        if (handled) {
            return result;
        }
    }

    if (overlapped != NULL && overlapped->hEvent == NULL && written != NULL && is_win9x()) {
        DWORD type = GetFileType(file);
        if (type == FILE_TYPE_DISK) {
            return file_io_at_offset(POSITION_WRITE, (FARPROC)native, file, buffer, bytes, written,
                (LONG)overlapped->Offset, (LONG)overlapped->OffsetHigh);
        }
        if (type == FILE_TYPE_PIPE) {
            overlapped = NULL;
        }
    }

    return native(file, buffer, bytes, written, overlapped);
}

static BOOL toolhelp_process_wide(HANDLE snapshot, PROCESSENTRY32W *wide, BOOL first)
{
    if (!is_win9x()) {
        typedef BOOL (WINAPI *process_entry_fn)(HANDLE, PROCESSENTRY32W *);
        process_entry_fn native = (process_entry_fn)kernel_proc(first ? "Process32FirstW" : "Process32NextW");
        return native(snapshot, wide);
    }

    if (wide == NULL || wide->dwSize != sizeof(*wide)) {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    PROCESSENTRY32 ansi = {0};
    ansi.dwSize = sizeof(ansi);
    // Windows 95 uses the previous process ID to advance the snapshot.
    if (!first) {
        ansi.th32ProcessID = wide->th32ProcessID;
    }
    if (!(first ? Process32First(snapshot, &ansi) : Process32Next(snapshot, &ansi))) {
        return FALSE;
    }

    memcpy(wide, &ansi, offsetof(PROCESSENTRY32, szExeFile));
    wide->dwSize = sizeof(*wide);
    return MultiByteToWideChar(CP_ACP, 0, ansi.szExeFile, -1, wide->szExeFile, MAX_PATH) != 0;
}

THUNK(BOOL, Process32FirstW, 8, (HANDLE snapshot, PROCESSENTRY32W *entry))
{
    return toolhelp_process_wide(snapshot, entry, TRUE);
}

THUNK(BOOL, Process32NextW, 8, (HANDLE snapshot, PROCESSENTRY32W *entry))
{
    return toolhelp_process_wide(snapshot, entry, FALSE);
}

static char *allocate_ansi(const wchar_t *wide, int length)
{
    int count = WideCharToMultiByte(CP_ACP, 0, wide, length, NULL, 0, NULL, NULL);
    if (count == 0)
        return NULL;

    HANDLE heap = GetProcessHeap();
    char *ansi = HeapAlloc(heap, 0, count);
    if (ansi == NULL) {
        SetLastError(ERROR_NOT_ENOUGH_MEMORY);
        return NULL;
    }

    BOOL replaced = FALSE;
    if (WideCharToMultiByte(CP_ACP, 0, wide, length, ansi, count, NULL, &replaced) == count && !replaced)
        return ansi;

    DWORD error = replaced ? ERROR_NO_UNICODE_TRANSLATION : GetLastError();
    HeapFree(heap, 0, ansi);
    SetLastError(error);
    return NULL;
}

static FARPROC registry_proc(const char *name)
{
    return GetProcAddress(GetModuleHandleA("advapi32.dll"), name);
}

static void free_registry_buffer(void *buffer)
{
    if (buffer != NULL) {
        HeapFree(GetProcessHeap(), 0, buffer);
    }
}

static BOOL registry_string_type(DWORD type)
{
    return type == REG_SZ || type == REG_EXPAND_SZ || type == REG_MULTI_SZ;
}

THUNK(LONG, RegCreateKeyExW, 36, (HKEY key, const wchar_t *name, DWORD reserved, wchar_t *class_name,
    DWORD options, REGSAM access, LPSECURITY_ATTRIBUTES security, HKEY *result, DWORD *disposition))
{
    if (!is_win9x()) {
        __typeof__(&RegCreateKeyExW) native = (__typeof__(&RegCreateKeyExW))registry_proc("RegCreateKeyExW");
        return native(key, name, reserved, class_name, options, access, security, result, disposition);
    }

    char *ansi_name = allocate_ansi(name, -1);
    if (ansi_name == NULL) {
        return GetLastError();
    }
    char *ansi_class = class_name == NULL ? NULL : allocate_ansi(class_name, -1);
    LONG status = class_name != NULL && ansi_class == NULL ? (LONG)GetLastError() :
        RegCreateKeyExA(key, ansi_name, reserved, ansi_class, options, access, security, result, disposition);
    free_registry_buffer(ansi_class);
    free_registry_buffer(ansi_name);
    return status;
}

THUNK(LONG, RegOpenKeyExW, 20, (HKEY key, const wchar_t *name, DWORD options, REGSAM access, HKEY *result))
{
    if (!is_win9x()) {
        __typeof__(&RegOpenKeyExW) native = (__typeof__(&RegOpenKeyExW))registry_proc("RegOpenKeyExW");
        return native(key, name, options, access, result);
    }

    char *ansi = name == NULL ? NULL : allocate_ansi(name, -1);
    if (name != NULL && ansi == NULL) {
        return GetLastError();
    }
    LONG status = RegOpenKeyExA(key, ansi, options, access, result);
    free_registry_buffer(ansi);
    return status;
}

THUNK(LONG, RegDeleteKeyW, 8, (HKEY key, const wchar_t *name))
{
    if (!is_win9x()) {
        __typeof__(&RegDeleteKeyW) native = (__typeof__(&RegDeleteKeyW))registry_proc("RegDeleteKeyW");
        return native(key, name);
    }

    char *ansi = allocate_ansi(name, -1);
    if (ansi == NULL) {
        return GetLastError();
    }
    LONG status = RegDeleteKeyA(key, ansi);
    free_registry_buffer(ansi);
    return status;
}

THUNK(LONG, RegDeleteValueW, 8, (HKEY key, const wchar_t *name))
{
    if (!is_win9x()) {
        __typeof__(&RegDeleteValueW) native = (__typeof__(&RegDeleteValueW))registry_proc("RegDeleteValueW");
        return native(key, name);
    }

    char *ansi = name == NULL ? NULL : allocate_ansi(name, -1);
    if (name != NULL && ansi == NULL) {
        return GetLastError();
    }
    LONG status = RegDeleteValueA(key, ansi);
    free_registry_buffer(ansi);
    return status;
}

THUNK(LONG, RegSetValueExW, 24, (HKEY key, const wchar_t *name, DWORD reserved, DWORD type,
    const BYTE *data, DWORD length))
{
    if (!is_win9x()) {
        __typeof__(&RegSetValueExW) native = (__typeof__(&RegSetValueExW))registry_proc("RegSetValueExW");
        return native(key, name, reserved, type, data, length);
    }

    char *ansi_name = name == NULL ? NULL : allocate_ansi(name, -1);
    if (name != NULL && ansi_name == NULL) {
        return GetLastError();
    }
    char *ansi_data = NULL;
    LONG status;
    if (length != 0 && registry_string_type(type)) {
        if (data == NULL || length % sizeof(wchar_t) != 0 || length / sizeof(wchar_t) > MAXLONG) {
            status = ERROR_INVALID_PARAMETER;
            goto done;
        }
        int wide_count = length / sizeof(wchar_t);
        ansi_data = allocate_ansi((const wchar_t *)data, wide_count);
        if (ansi_data == NULL) {
            status = GetLastError();
            goto done;
        }
        length = WideCharToMultiByte(CP_ACP, 0, (const wchar_t *)data, wide_count, NULL, 0, NULL, NULL);
        data = (const BYTE *)ansi_data;
    }
    status = RegSetValueExA(key, ansi_name, reserved, type, data, length);

done:
    free_registry_buffer(ansi_data);
    free_registry_buffer(ansi_name);
    return status;
}

THUNK(LONG, RegQueryValueExW, 24, (HKEY key, const wchar_t *name, DWORD *reserved, DWORD *type,
    BYTE *data, DWORD *length))
{
    if (!is_win9x()) {
        __typeof__(&RegQueryValueExW) native = (__typeof__(&RegQueryValueExW))registry_proc("RegQueryValueExW");
        return native(key, name, reserved, type, data, length);
    }
    if (reserved != NULL || (data != NULL && length == NULL)) {
        return ERROR_INVALID_PARAMETER;
    }

    char *ansi_name = name == NULL ? NULL : allocate_ansi(name, -1);
    if (name != NULL && ansi_name == NULL) {
        return GetLastError();
    }
    if (length == NULL) {
        LONG status = RegQueryValueExA(key, ansi_name, NULL, type, NULL, NULL);
        free_registry_buffer(ansi_name);
        return status;
    }

    // Read the byte count and type together so a concurrent writer cannot change the encoding we use.
    BYTE local[256];
    BYTE *ansi_data = local;
    DWORD capacity = sizeof(local), count, value_type;
    LONG status;
    for (;;) {
        count = capacity;
        status = RegQueryValueExA(key, ansi_name, NULL, &value_type, ansi_data, &count);
        if (status != ERROR_MORE_DATA || count <= capacity) {
            break;
        }
        if (ansi_data != local) {
            free_registry_buffer(ansi_data);
        }
        ansi_data = HeapAlloc(GetProcessHeap(), 0, count);
        if (ansi_data == NULL) {
            status = ERROR_NOT_ENOUGH_MEMORY;
            break;
        }
        capacity = count;
    }

    if (status == ERROR_SUCCESS) {
        DWORD output_capacity = data == NULL ? 0 : *length;
        if (type != NULL) {
            *type = value_type;
        }
        if (count != 0 && registry_string_type(value_type)) {
            int chars = count <= MAXLONG ? MultiByteToWideChar(CP_ACP, 0, (const char *)ansi_data, count, NULL, 0) : 0;
            if (chars == 0) {
                status = count <= MAXLONG ? (LONG)GetLastError() : ERROR_MORE_DATA;
            } else {
                *length = chars * sizeof(wchar_t);
                if (data != NULL) {
                    if (output_capacity < *length) {
                        status = ERROR_MORE_DATA;
                    } else if (MultiByteToWideChar(CP_ACP, 0, (const char *)ansi_data, count, (wchar_t *)data, chars) == 0) {
                        status = GetLastError();
                    }
                }
            }
        } else {
            *length = count;
            if (data != NULL) {
                if (output_capacity < count) {
                    status = ERROR_MORE_DATA;
                } else {
                    memcpy(data, ansi_data, count);
                }
            }
        }
    }

    if (ansi_data != local) {
        free_registry_buffer(ansi_data);
    }
    free_registry_buffer(ansi_name);
    return status;
}

static LONG copy_registry_name(const char *ansi, DWORD bytes, wchar_t *name, DWORD *capacity)
{
    int chars = bytes == 0 ? 0 : MultiByteToWideChar(CP_ACP, 0, ansi, bytes, NULL, 0);
    if (bytes != 0 && chars == 0) {
        return GetLastError();
    }
    if ((DWORD)chars >= *capacity) {
        return ERROR_MORE_DATA;
    }
    if (chars != 0 && MultiByteToWideChar(CP_ACP, 0, ansi, bytes, name, chars) == 0) {
        return GetLastError();
    }
    name[chars] = L'\0';
    *capacity = chars;
    return ERROR_SUCCESS;
}

THUNK(LONG, RegEnumKeyExW, 32, (HKEY key, DWORD index, wchar_t *name, DWORD *length, DWORD *reserved,
    wchar_t *class_name, DWORD *class_size, FILETIME *last_write))
{
    if (!is_win9x()) {
        __typeof__(&RegEnumKeyExW) native = (__typeof__(&RegEnumKeyExW))registry_proc("RegEnumKeyExW");
        return native(key, index, name, length, reserved, class_name, class_size, last_write);
    }
    if (class_name != NULL || class_size != NULL) {
        return ERROR_NOT_SUPPORTED;
    }
    char ansi[512];
    DWORD bytes = sizeof(ansi);
    LONG status = RegEnumKeyExA(key, index, ansi, &bytes, reserved, NULL, NULL, last_write);
    return status == ERROR_SUCCESS ? copy_registry_name(ansi, bytes, name, length) : status;
}

THUNK(LONG, RegEnumValueW, 32, (HKEY key, DWORD index, wchar_t *name, DWORD *length, DWORD *reserved,
    DWORD *type, BYTE *data, DWORD *data_length))
{
    if (!is_win9x()) {
        __typeof__(&RegEnumValueW) native = (__typeof__(&RegEnumValueW))registry_proc("RegEnumValueW");
        return native(key, index, name, length, reserved, type, data, data_length);
    }
    if (data != NULL || data_length != NULL) {
        return ERROR_NOT_SUPPORTED;
    }
    // The ANSI API treats the name buffer length as a signed 16-bit value.
    DWORD bytes = *length >= 16383 ? 32767 : *length * 2 + 1;
    char *ansi = HeapAlloc(GetProcessHeap(), 0, bytes);
    if (ansi == NULL) {
        return ERROR_NOT_ENOUGH_MEMORY;
    }
    LONG status = RegEnumValueA(key, index, ansi, &bytes, reserved, type, NULL, NULL);
    if (status == ERROR_SUCCESS) {
        status = copy_registry_name(ansi, bytes, name, length);
    }
    free_registry_buffer(ansi);
    return status;
}

THUNK(LONG, RegQueryInfoKeyW, 48, (HKEY key, wchar_t *class_name, DWORD *class_size, DWORD *reserved,
    DWORD *subkeys, DWORD *max_subkey, DWORD *max_class, DWORD *values, DWORD *max_value_name,
    DWORD *max_value_data, DWORD *descriptor_size, FILETIME *last_write))
{
    if (!is_win9x()) {
        __typeof__(&RegQueryInfoKeyW) native = (__typeof__(&RegQueryInfoKeyW))registry_proc("RegQueryInfoKeyW");
        return native(key, class_name, class_size, reserved, subkeys, max_subkey, max_class, values,
            max_value_name, max_value_data, descriptor_size, last_write);
    }
    if (class_name != NULL || class_size != NULL || max_subkey != NULL || max_class != NULL ||
        max_value_name != NULL || max_value_data != NULL) {
        return ERROR_NOT_SUPPORTED;
    }
    return RegQueryInfoKeyA(key, NULL, NULL, reserved, subkeys, NULL, NULL, values,
        NULL, NULL, descriptor_size, last_write);
}

/* Win9x exports these wide environment functions as unimplemented stubs. */
THUNK(DWORD, ExpandEnvironmentStringsW, 12, (const wchar_t *source, wchar_t *dest, DWORD capacity))
{
    if (!is_win9x()) {
        typedef DWORD (WINAPI *expand_fn)(const wchar_t *, wchar_t *, DWORD);
        expand_fn native = (expand_fn)kernel_proc("ExpandEnvironmentStringsW");
        return native(source, dest, capacity);
    }

    char *ansi_source = allocate_ansi(source, -1);
    if (ansi_source == NULL) {
        return 0;
    }

    char local[128];
    char *expanded = local;
    DWORD ansi_capacity = sizeof(local);
    HANDLE heap = GetProcessHeap();
    DWORD result = 0;
    for (;;) {
        DWORD length = ExpandEnvironmentStringsA(ansi_source, expanded, ansi_capacity);
        if (length == 0) {
            break;
        }
        if (length <= ansi_capacity) {
            int required = MultiByteToWideChar(CP_ACP, 0, expanded, -1, NULL, 0);
            if (required == 0 || (DWORD)required > capacity) {
                result = required;
            } else {
                result = MultiByteToWideChar(CP_ACP, 0, expanded, -1, dest, required);
            }
            break;
        }
        if (expanded != local) {
            HeapFree(heap, 0, expanded);
        }
        ansi_capacity = length;
        expanded = HeapAlloc(heap, 0, ansi_capacity);
        if (expanded == NULL) {
            SetLastError(ERROR_NOT_ENOUGH_MEMORY);
            break;
        }
    }

    DWORD error = GetLastError();
    if (expanded != local && expanded != NULL) {
        HeapFree(heap, 0, expanded);
    }
    HeapFree(heap, 0, ansi_source);
    SetLastError(error);
    return result;
}

THUNK(DWORD, GetEnvironmentVariableW, 12, (const wchar_t *name, wchar_t *value, DWORD capacity))
{
    if (!is_win9x()) {
        typedef DWORD (WINAPI *get_variable_fn)(const wchar_t *, wchar_t *, DWORD);
        get_variable_fn native = (get_variable_fn)kernel_proc("GetEnvironmentVariableW");
        return native(name, value, capacity);
    }

    char *ansi_name = allocate_ansi(name, -1);
    if (ansi_name == NULL) {
        return 0;
    }

    char local_value[128];
    char *ansi_value = local_value;
    DWORD ansi_capacity = sizeof(local_value);
    HANDLE heap = GetProcessHeap();
    DWORD result = 0;
    for (;;) {
        ansi_value[0] = '\0';
        SetLastError(ERROR_SUCCESS);
        DWORD length = GetEnvironmentVariableA(ansi_name, ansi_value, ansi_capacity);
        if (length == 0 && GetLastError() != ERROR_SUCCESS) {
            break;
        }

        if (length < ansi_capacity) {
            int required = MultiByteToWideChar(CP_ACP, 0, ansi_value, -1, NULL, 0);
            if (required == 0 || (DWORD)required > capacity) {
                result = required;
            } else {
                int count = MultiByteToWideChar(CP_ACP, 0, ansi_value, -1, value, required);
                result = count == 0 ? 0 : count - 1;
            }
            break;
        }

        if (ansi_value != local_value) {
            HeapFree(heap, 0, ansi_value);
        }
        ansi_capacity = length;
        ansi_value = HeapAlloc(heap, 0, ansi_capacity);
        if (ansi_value == NULL) {
            SetLastError(ERROR_NOT_ENOUGH_MEMORY);
            break;
        }
    }

    DWORD error = GetLastError();
    if (ansi_value != local_value && ansi_value != NULL) {
        HeapFree(heap, 0, ansi_value);
    }
    HeapFree(heap, 0, ansi_name);
    SetLastError(error);
    return result;
}

THUNK(BOOL, SetEnvironmentVariableW, 8, (const wchar_t *name, const wchar_t *value))
{
    if (!is_win9x()) {
        typedef BOOL (WINAPI *set_variable_fn)(const wchar_t *, const wchar_t *);
        set_variable_fn native = (set_variable_fn)kernel_proc("SetEnvironmentVariableW");
        return native(name, value);
    }

    char *ansi_name = allocate_ansi(name, -1);
    if (ansi_name == NULL) {
        return FALSE;
    }

    char *ansi_value = value == NULL ? NULL : allocate_ansi(value, -1);
    BOOL result = FALSE;
    if (value == NULL || ansi_value != NULL) {
        result = SetEnvironmentVariableA(ansi_name, ansi_value);
    }

    DWORD error = GetLastError();
    HANDLE heap = GetProcessHeap();
    if (ansi_value != NULL) {
        HeapFree(heap, 0, ansi_value);
    }
    HeapFree(heap, 0, ansi_name);
    SetLastError(error);
    return result;
}

THUNK(DWORD, GetCurrentDirectoryW, 8, (DWORD capacity, wchar_t *buffer))
{
    if (!is_win9x()) {
        typedef DWORD (WINAPI *get_directory)(DWORD, wchar_t *);
        return ((get_directory)kernel_proc("GetCurrentDirectoryW"))(capacity, buffer);
    }

    char ansi[MAX_PATH * 2];
    DWORD length = GetCurrentDirectoryA(sizeof(ansi), ansi);
    if (length == 0)
        return 0;
    if (length >= sizeof(ansi)) {
        SetLastError(ERROR_FILENAME_EXCED_RANGE);
        return 0;
    }
    int required = MultiByteToWideChar(CP_ACP, 0, ansi, -1, NULL, 0);
    if (required == 0 || (DWORD)required > capacity)
        return required;
    int converted = MultiByteToWideChar(CP_ACP, 0, ansi, -1, buffer, required);
    return converted == 0 ? 0 : converted - 1;
}

THUNK(BOOL, CreateProcessW, 40, (const wchar_t *application, wchar_t *command, SECURITY_ATTRIBUTES *process_security,
    SECURITY_ATTRIBUTES *thread_security, BOOL inherit, DWORD flags, void *environment, const wchar_t *directory,
    STARTUPINFOW *startup, PROCESS_INFORMATION *process))
{
    if (!is_win9x()) {
        typedef BOOL (WINAPI *create_process)(const wchar_t *, wchar_t *, SECURITY_ATTRIBUTES *,
            SECURITY_ATTRIBUTES *, BOOL, DWORD, void *, const wchar_t *, STARTUPINFOW *, PROCESS_INFORMATION *);
        return ((create_process)kernel_proc("CreateProcessW"))(application, command, process_security,
            thread_security, inherit, flags, environment, directory, startup, process);
    }

    if (flags & EXTENDED_STARTUPINFO_PRESENT) {
        SetLastError(ERROR_NOT_SUPPORTED);
        return FALSE;
    }
    if (startup == NULL || startup->cb != sizeof(*startup)) {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    const wchar_t *strings[] = { application, command, directory, startup->lpDesktop, startup->lpTitle };
    char *ansi[sizeof(strings) / sizeof(strings[0])] = {0};
    char *ansi_environment = NULL;
    char empty_environment[2] = {0};
    BOOL result = FALSE;
    DWORD error;

    for (unsigned i = 0; i < sizeof(strings) / sizeof(strings[0]); ++i) {
        if (strings[i] != NULL && (ansi[i] = allocate_ansi(strings[i], -1)) == NULL)
            goto release;
    }
    if (environment != NULL && (flags & CREATE_UNICODE_ENVIRONMENT)) {
        const wchar_t *begin = environment, *end = begin;
        while (*end) {
            while (*end)
                ++end;
            ++end;
        }
        if (end == begin) {
            /* An empty managed string supplies just one UTF-16 terminator. */
            environment = empty_environment;
        } else {
            int length = (int)(end - begin) + 1;
            ansi_environment = allocate_ansi(begin, length);
            if (ansi_environment == NULL) {
                goto release;
            }
            environment = ansi_environment;
        }
    }

    STARTUPINFOA native;
    memcpy(&native, startup, sizeof(native));
    native.lpReserved = NULL;
    native.lpDesktop = ansi[3];
    native.lpTitle = ansi[4];

    if (process_security != NULL && process_security->nLength == 0)
        process_security = NULL;
    if (thread_security != NULL && thread_security->nLength == 0)
        thread_security = NULL;
    result = CreateProcessA(ansi[0], ansi[1], process_security, thread_security, inherit,
        flags & ~CREATE_UNICODE_ENVIRONMENT, environment, ansi[2], &native, process);

release:
    error = GetLastError();
    HANDLE heap = GetProcessHeap();
    for (unsigned i = 0; i < sizeof(ansi) / sizeof(ansi[0]); ++i) {
        if (ansi[i] != NULL)
            HeapFree(heap, 0, ansi[i]);
    }
    if (ansi_environment != NULL)
        HeapFree(heap, 0, ansi_environment);
    SetLastError(error);
    return result;
}

/* The static CRT normally inspects the x86 NT PEB for these process flags.
   The checks are false on Win9x, which has no NT PEB. */
static const BYTE *nt_peb(void)
{
    const BYTE *peb;
    __asm__ ("movl %%fs:0x30, %0" : "=r"(peb));
    return peb;
}

bool __cdecl __acrt_app_verifier_enabled(void)
{
    const DWORD application_verifier = 0x100;
    return !is_win9x() && (*(const DWORD *)(nt_peb() + 0x68) & application_verifier) != 0;
}

bool __cdecl __acrt_is_secure_process(void)
{
    const DWORD secure_process = 0x80000000;
    if (is_win9x())
        return false;

    const BYTE *parameters = *(const BYTE *const *)(nt_peb() + 0x10);
    return (*(const DWORD *)(parameters + 0x08) & secure_process) != 0;
}

/* This object registers no x86 SEH handlers. */
__asm__(".def @feat.00; .scl 3; .type 0; .endef\n.set @feat.00, 1");

#ifdef WIN95_NATIVE_AOT
#include "Win95Compat.inc"
#endif

/* The corresponding wide file APIs are missing or stubbed on Windows 95. */
#define WIN9X_PATH_THUNK(name) \
    THUNK(BOOL, name##W, 4, (const wchar_t *path)) \
    { \
        if (!is_win9x()) { \
            typedef BOOL (WINAPI *path_fn)(const wchar_t *); \
            path_fn native = (path_fn)kernel_proc(#name "W"); \
            return native(path); \
        } \
        char ansi[MAX_PATH * 2]; \
        return ansi_path(path, ansi, sizeof(ansi)) && name##A(ansi); \
    }

WIN9X_PATH_THUNK(RemoveDirectory)
WIN9X_PATH_THUNK(DeleteFile)
WIN9X_PATH_THUNK(SetCurrentDirectory)

#undef WIN9X_PATH_THUNK

/* Win95 OSR2.1 and Win98 SE export these wide drive queries as stubs. */
THUNK(UINT, GetDriveTypeW, 4, (const wchar_t *root))
{
    if (!is_win9x()) {
        typedef UINT (WINAPI *get_drive_type_fn)(const wchar_t *);
        get_drive_type_fn native = (get_drive_type_fn)kernel_proc("GetDriveTypeW");
        return native(root);
    }

    char ansi[MAX_PATH * 2];
    if (root != NULL && !ansi_path(root, ansi, sizeof(ansi))) {
        return DRIVE_NO_ROOT_DIR;
    }
    return GetDriveTypeA(root != NULL ? ansi : NULL);
}

THUNK(BOOL, GetDiskFreeSpaceExW, 16, (const wchar_t *path, ULARGE_INTEGER *available,
    ULARGE_INTEGER *total, ULARGE_INTEGER *free_bytes))
{
    if (!is_win9x()) {
        typedef BOOL (WINAPI *get_space_fn)(const wchar_t *, ULARGE_INTEGER *, ULARGE_INTEGER *, ULARGE_INTEGER *);
        get_space_fn native = (get_space_fn)kernel_proc("GetDiskFreeSpaceExW");
        return native(path, available, total, free_bytes);
    }

    char ansi[MAX_PATH * 2];
    if (path != NULL && !ansi_path(path, ansi, sizeof(ansi))) {
        return FALSE;
    }
    return GetDiskFreeSpaceExA(path != NULL ? ansi : NULL, available, total, free_bytes);
}

static BOOL copy_volume_string(const char *ansi, wchar_t *wide, DWORD capacity)
{
    if (wide == NULL) {
        return TRUE;
    }
    int required = MultiByteToWideChar(CP_ACP, 0, ansi, -1, NULL, 0);
    if (required == 0) {
        return FALSE;
    }
    if ((DWORD)required > capacity) {
        SetLastError(ERROR_MORE_DATA);
        return FALSE;
    }
    return MultiByteToWideChar(CP_ACP, 0, ansi, -1, wide, required) != 0;
}

THUNK(BOOL, GetVolumeInformationW, 32, (const wchar_t *root, wchar_t *label, DWORD label_size,
    DWORD *serial, DWORD *max_component, DWORD *flags, wchar_t *format, DWORD format_size))
{
    if (!is_win9x()) {
        typedef BOOL (WINAPI *get_volume_fn)(const wchar_t *, wchar_t *, DWORD, DWORD *, DWORD *, DWORD *, wchar_t *, DWORD);
        get_volume_fn native = (get_volume_fn)kernel_proc("GetVolumeInformationW");
        return native(root, label, label_size, serial, max_component, flags, format, format_size);
    }

    char ansi_root[MAX_PATH * 2], ansi_label[MAX_PATH * 2], ansi_format[MAX_PATH * 2];
    if (root != NULL && !ansi_path(root, ansi_root, sizeof(ansi_root))) {
        return FALSE;
    }
    if (!GetVolumeInformationA(root != NULL ? ansi_root : NULL,
        label != NULL ? ansi_label : NULL, label != NULL ? sizeof(ansi_label) : 0,
        serial, max_component, flags,
        format != NULL ? ansi_format : NULL, format != NULL ? sizeof(ansi_format) : 0)) {
        return FALSE;
    }
    return copy_volume_string(ansi_label, label, label_size) && copy_volume_string(ansi_format, format, format_size);
}

THUNK(BOOL, CreateDirectoryW, 8, (const wchar_t *path, SECURITY_ATTRIBUTES *security))
{
    if (!is_win9x()) {
        typedef BOOL (WINAPI *create_directory_fn)(const wchar_t *, SECURITY_ATTRIBUTES *);
        create_directory_fn native = (create_directory_fn)kernel_proc("CreateDirectoryW");
        return native(path, security);
    }
    char ansi[MAX_PATH * 2];
    return ansi_path(path, ansi, sizeof(ansi)) && CreateDirectoryA(ansi, security);
}

THUNK(BOOL, CopyFileExW, 24, (const wchar_t *source, const wchar_t *destination,
    LPPROGRESS_ROUTINE progress, void *data, BOOL *canceled, DWORD flags))
{
    if (!is_win9x()) {
        typedef BOOL (WINAPI *copy_file_fn)(const wchar_t *, const wchar_t *, LPPROGRESS_ROUTINE, void *, BOOL *, DWORD);
        copy_file_fn native = (copy_file_fn)kernel_proc("CopyFileExW");
        return native(source, destination, progress, data, canceled, flags);
    }

    char src[MAX_PATH * 2], dst[MAX_PATH * 2];
    if (!ansi_path(source, src, sizeof(src)) || !ansi_path(destination, dst, sizeof(dst))) {
        return FALSE;
    }
    typedef BOOL (WINAPI *copy_file_ansi_fn)(const char *, const char *, LPPROGRESS_ROUTINE, void *, BOOL *, DWORD);
    copy_file_ansi_fn native = (copy_file_ansi_fn)kernel_proc("CopyFileExA");
    if (native != NULL) {
        BOOL result = native(src, dst, progress, data, canceled, flags);
        if (result || GetLastError() != ERROR_CALL_NOT_IMPLEMENTED) {
            return result;
        }
    }

    if (canceled != NULL && *canceled) {
        SetLastError(ERROR_REQUEST_ABORTED);
        return FALSE;
    }
    if (progress != NULL || (flags & ~COPY_FILE_FAIL_IF_EXISTS) != 0) {
        SetLastError(ERROR_NOT_SUPPORTED);
        return FALSE;
    }
    return CopyFileA(src, dst, (flags & COPY_FILE_FAIL_IF_EXISTS) != 0);
}

static BOOL move_file_ansi(const char *source, const char *destination, DWORD flags)
{
    if (MoveFileA(source, destination)) {
        return TRUE;
    }
    if (!(flags & MOVEFILE_COPY_ALLOWED) || GetLastError() != ERROR_NOT_SAME_DEVICE ||
        !CopyFileA(source, destination, TRUE)) {
        return FALSE;
    }

    /* MOVEFILE_COPY_ALLOWED succeeds if copying succeeds and deletion fails. */
    DeleteFileA(source);
    return TRUE;
}

static BOOL move_file_replacing_ansi(const char *source, const char *destination, DWORD flags)
{
    DWORD attributes = GetFileAttributesA(destination);
    if (attributes == INVALID_FILE_ATTRIBUTES) {
        return FALSE;
    }
    if (attributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_READONLY)) {
        SetLastError(ERROR_ACCESS_DENIED);
        return FALSE;
    }

    char directory[MAX_PATH], backup[MAX_PATH];
    char *name = NULL;
    DWORD size = GetFullPathNameA(destination, sizeof(directory), directory, &name);
    if (size == 0) {
        return FALSE;
    }
    if (size >= sizeof(directory) || name == NULL) {
        SetLastError(ERROR_INVALID_NAME);
        return FALSE;
    }
    *name = '\0';
    if (GetTempFileNameA(directory, "AOT", 0, backup) == 0 ||
        !DeleteFileA(backup) || !MoveFileA(destination, backup)) {
        return FALSE;
    }

    /* Win9x lacks atomic replacement. Keep the old file until the new name
       is in place, and leave the backup intact if another writer prevents rollback. */
    if (!move_file_ansi(source, destination, flags)) {
        DWORD error = GetLastError();
        MoveFileA(backup, destination);
        SetLastError(error);
        return FALSE;
    }
    DeleteFileA(backup);
    return TRUE;
}

THUNK(BOOL, MoveFileExW, 12, (const wchar_t *source, const wchar_t *destination, DWORD flags))
{
    if (!is_win9x()) {
        typedef BOOL (WINAPI *move_file_fn)(const wchar_t *, const wchar_t *, DWORD);
        move_file_fn native = (move_file_fn)kernel_proc("MoveFileExW");
        return native(source, destination, flags);
    }

    char src[MAX_PATH * 2], dst[MAX_PATH * 2];
    if (!ansi_path(source, src, sizeof(src)) || !ansi_path(destination, dst, sizeof(dst))) {
        return FALSE;
    }
    typedef BOOL (WINAPI *move_file_ansi_fn)(const char *, const char *, DWORD);
    move_file_ansi_fn native = (move_file_ansi_fn)kernel_proc("MoveFileExA");
    if (native != NULL) {
        BOOL result = native(src, dst, flags);
        if (result || GetLastError() != ERROR_CALL_NOT_IMPLEMENTED) {
            return result;
        }
    }

    if ((flags & ~(MOVEFILE_COPY_ALLOWED | MOVEFILE_REPLACE_EXISTING)) != 0) {
        SetLastError(ERROR_NOT_SUPPORTED);
        return FALSE;
    }
    if (move_file_ansi(src, dst, flags)) {
        return TRUE;
    }
    DWORD error = GetLastError();
    if ((flags & MOVEFILE_REPLACE_EXISTING) && (error == ERROR_FILE_EXISTS || error == ERROR_ALREADY_EXISTS)) {
        return move_file_replacing_ansi(src, dst, flags);
    }
    return FALSE;
}

static BOOL win9x_local_socket(HMODULE winsock, SOCKET socket)
{
    /* Windows 95 (4.0) and Windows 98 (4.10). */
    DWORD version = GetVersion() & 0x8000ffffu;
    if (version != 0x80000004u && version != 0x80000a04u) {
        return FALSE;
    }
    typedef int (WSAAPI *get_option_fn)(SOCKET, int, int, char *, int *);
    get_option_fn get_option = (get_option_fn)GetProcAddress(winsock, "getsockopt");
    WSAPROTOCOL_INFOW info;
    int info_size = sizeof(info);
    if (get_option == NULL || get_option(socket, SOL_SOCKET, SO_PROTOCOL_INFOW, (char *)&info, &info_size) != 0 ||
        info_size != sizeof(info)) {
        return FALSE;
    }

    /* The Microsoft Winsock 2 IPv4 base provider on Windows 95 and 98 keeps
       these descriptors process-local when CreateProcess inherits file handles. */
    static const GUID provider = {0xff017de0, 0xcae9, 0x11cf, {0x8a, 0x99, 0x00, 0xaa, 0x00, 0x62, 0xc6, 0x09}};
    return info.ProtocolChain.ChainLen == BASE_PROTOCOL && info.iAddressFamily == AF_INET &&
        ((info.iSocketType == SOCK_STREAM && info.iProtocol == IPPROTO_TCP) ||
         (info.iSocketType == SOCK_DGRAM && info.iProtocol == IPPROTO_UDP)) &&
        memcmp(&info.ProviderId, &provider, sizeof(provider)) == 0;
}

THUNK(SOCKET, WSASocketW, 24, (int family, int type, int protocol, WSAPROTOCOL_INFOW *info, GROUP group, DWORD flags))
{
    typedef SOCKET (WSAAPI *socket_fn)(int, int, int, WSAPROTOCOL_INFOW *, GROUP, DWORD);
    HMODULE winsock = GetModuleHandleA("ws2_32.dll");
    socket_fn create_socket = (socket_fn)GetProcAddress(winsock, "WSASocketW");
    if (create_socket == NULL) {
        SetLastError(WSAEOPNOTSUPP);
        return INVALID_SOCKET;
    }

    SOCKET socket = create_socket(family, type, protocol, info, group, flags);
    if (socket != INVALID_SOCKET || !(flags & WSA_FLAG_NO_HANDLE_INHERIT) || GetLastError() != WSAEINVAL ||
        !is_win9x()) {
        return socket;
    }

    typedef int (WSAAPI *close_socket_fn)(SOCKET);
    close_socket_fn close_socket = (close_socket_fn)GetProcAddress(winsock, "closesocket");
    if (close_socket == NULL) {
        SetLastError(WSAEOPNOTSUPP);
        return INVALID_SOCKET;
    }
    socket = create_socket(family, type, protocol, info, group, flags & ~WSA_FLAG_NO_HANDLE_INHERIT);
    if (socket == INVALID_SOCKET || SetHandleInformation((HANDLE)socket, HANDLE_FLAG_INHERIT, 0)) {
        return socket;
    }

    DWORD error = GetLastError();
    if (error == ERROR_CALL_NOT_IMPLEMENTED && info == NULL && group == 0 && win9x_local_socket(winsock, socket)) {
        return socket;
    }
    close_socket(socket);
    SetLastError(error);
    return INVALID_SOCKET;
}
