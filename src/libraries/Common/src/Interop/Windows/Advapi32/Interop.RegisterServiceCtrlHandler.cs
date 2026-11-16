// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System;
using System.Runtime.InteropServices;

internal static partial class Interop
{
    internal static partial class Advapi32
    {
        public delegate void ServiceControlCallback(int control);

        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        [LibraryImport(Libraries.Advapi32, EntryPoint = "RegisterServiceCtrlHandlerW", SetLastError = true, StringMarshalling = StringMarshalling.Utf16)]
        public static partial IntPtr RegisterServiceCtrlHandler(string serviceName, ServiceControlCallback callback);
    }
}
