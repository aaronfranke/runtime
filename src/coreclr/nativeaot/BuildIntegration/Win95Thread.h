// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

#pragma once

typedef HANDLE (WINAPI *Win95CreateThreadFn)(SECURITY_ATTRIBUTES *, SIZE_T, LPTHREAD_START_ROUTINE, void *, DWORD, DWORD *);

HANDLE Win95CreateThread(Win95CreateThreadFn native, SECURITY_ATTRIBUTES *security, SIZE_T size,
    LPTHREAD_START_ROUTINE start, void *argument, DWORD flags, DWORD *id);
