// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <string.h>

#if defined(_WIN64)
#define COFF_NAME(name, bytes) #name
#else
#define COFF_NAME(name, bytes) "_" #name "@" #bytes
__asm__(".def @feat.00; .scl 3; .type 0; .endef\n.set @feat.00, 1");
#endif

/* Resolve both direct calls and import references to the compatibility functions. */
#define THUNK(ret, name, bytes, args) \
    ret WINAPI compat_##name args __asm__(COFF_NAME(name, bytes)); \
    ret (WINAPI *const iat_##name) args __asm__("__imp_" COFF_NAME(name, bytes)) = compat_##name; \
    ret WINAPI compat_##name args

#include "WinLegacySystemCompat.inc"

/* EventSetInformation arrived in Windows 8. ETW provider traits are optional
   on Windows 7, so report unsupported rather than failing EventSource startup.
   NT4/NT5/9x also lack mandatory modern ETW registration APIs; this adapter alone
   does not enable native diagnostics on those older profiles. */
typedef ULONG (WINAPI *event_set_information_fn)(ULONGLONG, ULONG, void *, ULONG);
static INIT_ONCE event_information_once = INIT_ONCE_STATIC_INIT;
static event_set_information_fn native_event_information;

static BOOL CALLBACK resolve_event_information(PINIT_ONCE once, void *parameter, void **context)
{
    /* Retain one module reference for the lifetime of this direct-import adapter. */
    HMODULE advapi = LoadLibraryExW(L"advapi32.dll", NULL, LOAD_LIBRARY_SEARCH_SYSTEM32);
    if (advapi == NULL) {
        return FALSE;
    }
    native_event_information = (event_set_information_fn)GetProcAddress(advapi, "EventSetInformation");
    return TRUE;
}

THUNK(ULONG, EventSetInformation, 20, (ULONGLONG registration, ULONG information_class, void *information, ULONG length))
{
    if (!InitOnceExecuteOnce(&event_information_once, resolve_event_information, NULL, NULL)) {
        return GetLastError();
    }
    if (native_event_information != NULL) {
        return native_event_information(registration, information_class, information, length);
    }
    return ERROR_NOT_SUPPORTED;
}

typedef BOOL (WINAPI *wait_address_fn)(volatile void *, void *, SIZE_T, DWORD);
typedef void (WINAPI *wake_address_fn)(void *);
static INIT_ONCE wait_functions_once = INIT_ONCE_STATIC_INIT;
static wait_address_fn native_wait;
static wake_address_fn native_wake;

static BOOL CALLBACK resolve_wait_functions(PINIT_ONCE once, void *parameter, void **context)
{
    HMODULE base = GetModuleHandleW(L"kernelbase.dll");
    native_wait = (wait_address_fn)GetProcAddress(base, "WaitOnAddress");
    native_wake = (wake_address_fn)GetProcAddress(base, "WakeByAddressSingle");
    return TRUE;
}

typedef struct address_waiter {
    struct address_waiter *next;
    volatile void *address;
    CONDITION_VARIABLE condition;
    BOOL signaled;
} address_waiter;

static SRWLOCK wait_lock = SRWLOCK_INIT;
static address_waiter *waiters;

THUNK(BOOL, WaitOnAddress, 16, (volatile void *address, void *comparison, SIZE_T size, DWORD timeout))
{
    InitOnceExecuteOnce(&wait_functions_once, resolve_wait_functions, NULL, NULL);
    if (native_wait && native_wake) {
        return native_wait(address, comparison, size, timeout);
    }
    if (size != 1 && size != 2 && size != 4 && size != 8) {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    /* Windows 7 has condition variables and SRW locks, but no address waits.
       Hold the lock through the comparison and queue insertion to avoid losing
       a wake between those operations. */
    AcquireSRWLockExclusive(&wait_lock);
    const volatile BYTE *value = address;
    const BYTE *expected = comparison;
    for (SIZE_T i = 0; i < size; ++i) {
        if (value[i] != expected[i]) {
            ReleaseSRWLockExclusive(&wait_lock);
            return TRUE;
        }
    }

    address_waiter waiter = {waiters, address, CONDITION_VARIABLE_INIT, FALSE};
    waiters = &waiter;
    BOOL result = SleepConditionVariableSRW(&waiter.condition, &wait_lock, timeout, 0);
    DWORD error = result ? ERROR_SUCCESS : GetLastError();

    address_waiter **entry = &waiters;
    while (*entry != &waiter) {
        entry = &(*entry)->next;
    }
    *entry = waiter.next;
    ReleaseSRWLockExclusive(&wait_lock);
    if (!result) {
        SetLastError(error);
    }
    return result;
}

THUNK(void, WakeByAddressSingle, 4, (void *address))
{
    InitOnceExecuteOnce(&wait_functions_once, resolve_wait_functions, NULL, NULL);
    if (native_wait && native_wake) {
        native_wake(address);
        return;
    }

    AcquireSRWLockExclusive(&wait_lock);
    for (address_waiter *waiter = waiters; waiter; waiter = waiter->next) {
        if (waiter->address == address && !waiter->signaled) {
            waiter->signaled = TRUE;
            WakeConditionVariable(&waiter->condition);
            break;
        }
    }
    ReleaseSRWLockExclusive(&wait_lock);
}
