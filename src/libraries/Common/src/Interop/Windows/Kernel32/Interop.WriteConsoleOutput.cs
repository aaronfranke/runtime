// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System;
using System.Runtime.InteropServices;

internal static partial class Interop
{
    internal static partial class Kernel32
    {
        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        [LibraryImport(Libraries.Kernel32, EntryPoint = "WriteConsoleOutputW", SetLastError = true, StringMarshalling = StringMarshalling.Utf16)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static unsafe partial bool WriteConsoleOutputUnicode(IntPtr hConsoleOutput, CHAR_INFO* buffer, COORD bufferSize, COORD bufferCoord, ref SMALL_RECT writeRegion);

        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        [LibraryImport(Libraries.Kernel32, EntryPoint = "WriteConsoleOutputA", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static unsafe partial bool WriteConsoleOutputAnsi(IntPtr hConsoleOutput, CHAR_INFO* buffer, COORD bufferSize, COORD bufferCoord, ref SMALL_RECT writeRegion);

        // ConsolePal copies opaque CHAR_INFO cells between these paired APIs.
        // Win9x has Unicode stubs; keep its code-page bytes and attributes unchanged.
        internal static unsafe bool WriteConsoleOutput(IntPtr hConsoleOutput, CHAR_INFO* buffer, COORD bufferSize, COORD bufferCoord, ref SMALL_RECT writeRegion)
        {
            if (Environment.OSVersion.Platform == PlatformID.Win32Windows)
            {
                return WriteConsoleOutputAnsi(hConsoleOutput, buffer, bufferSize, bufferCoord, ref writeRegion);
            }
            return WriteConsoleOutputUnicode(hConsoleOutput, buffer, bufferSize, bufferCoord, ref writeRegion);
        }
    }
}
