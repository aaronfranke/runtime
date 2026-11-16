// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace System.Diagnostics
{
    internal static partial class NtProcessManager
    {
        private static readonly bool s_useLegacyPsapi = !ProcessManager.HasKernel32Export("K32EnumProcessModulesEx");

        private static bool EnumProcessModules(SafeProcessHandle process, IntPtr[]? modules, int size, out int needed) =>
            s_useLegacyPsapi ? LegacyPsapi.EnumProcessModules(process, modules, size, out needed) :
            Interop.Kernel32.EnumProcessModulesEx(process, modules, size, out needed, Interop.Kernel32.LIST_MODULES_ALL);

        private static partial class LegacyPsapi
        {
            // Windows 7 added the K32 exports. Earlier NT releases expose the module APIs through PSAPI.
            private const string Library = "psapi.dll";

            [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
            [LibraryImport(Library, SetLastError = true)]
            [return: MarshalAs(UnmanagedType.Bool)]
            internal static partial bool EnumProcessModules(SafeProcessHandle process, IntPtr[]? modules, int size, out int needed);

            [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
            [LibraryImport(Library, SetLastError = true)]
            [return: MarshalAs(UnmanagedType.Bool)]
            internal static partial bool GetModuleInformation(SafeProcessHandle process, IntPtr module,
                out Interop.Kernel32.NtModuleInfo info, int size);

            [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
            [LibraryImport(Library, EntryPoint = "GetModuleBaseNameW", SetLastError = true, StringMarshalling = StringMarshalling.Utf16)]
            internal static partial int GetModuleBaseName(SafeProcessHandle process, IntPtr module, [Out] char[] name, int size);

            [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
            [LibraryImport(Library, EntryPoint = "GetModuleFileNameExW", SetLastError = true, StringMarshalling = StringMarshalling.Utf16)]
            internal static partial int GetModuleFileNameEx(SafeProcessHandle process, IntPtr module, [Out] char[] path, int size);
        }
    }
}
