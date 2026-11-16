// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.Runtime.InteropServices;

internal static partial class Interop
{
    internal static partial class Kernel32
    {
        internal static void OutputDebugString(string message)
        {
            // Win9x exports the Unicode entry point but does not deliver its output.
            if (System.Environment.OSVersion.Platform == System.PlatformID.Win32Windows)
            {
                OutputDebugStringA(message);
            }
            else
            {
                OutputDebugStringW(message);
            }
        }

        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        [LibraryImport(Libraries.Kernel32, EntryPoint = "OutputDebugStringW", StringMarshalling = StringMarshalling.Utf16)]
        private static partial void OutputDebugStringW(string message);

        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        [LibraryImport(Libraries.Kernel32, EntryPoint = "OutputDebugStringA")]
        private static partial void OutputDebugStringA([MarshalAs(UnmanagedType.LPStr)] string message);
    }
}
