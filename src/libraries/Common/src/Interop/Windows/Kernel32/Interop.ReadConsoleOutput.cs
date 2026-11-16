// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System;
using System.Runtime.InteropServices;

internal static partial class Interop
{
    internal static partial class Kernel32
    {
        [StructLayout(LayoutKind.Sequential)]
        internal struct CHAR_INFO
        {
            private ushort charData;
            private short attributes;
        }

        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        [LibraryImport(Libraries.Kernel32, EntryPoint = "ReadConsoleOutputW", SetLastError = true, StringMarshalling = StringMarshalling.Utf16)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static unsafe partial bool ReadConsoleOutputUnicode(IntPtr hConsoleOutput, CHAR_INFO* pBuffer, COORD bufferSize, COORD bufferCoord, ref SMALL_RECT readRegion);

        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        [LibraryImport(Libraries.Kernel32, EntryPoint = "ReadConsoleOutputA", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static unsafe partial bool ReadConsoleOutputAnsi(IntPtr hConsoleOutput, CHAR_INFO* pBuffer, COORD bufferSize, COORD bufferCoord, ref SMALL_RECT readRegion);

        // ConsolePal copies opaque CHAR_INFO cells between these paired APIs.
        // Win9x has Unicode stubs; keep its code-page bytes and attributes unchanged.
        internal static unsafe bool ReadConsoleOutput(IntPtr hConsoleOutput, CHAR_INFO* pBuffer, COORD bufferSize, COORD bufferCoord, ref SMALL_RECT readRegion)
        {
            if (Environment.OSVersion.Platform == PlatformID.Win32Windows)
            {
                return ReadConsoleOutputAnsi(hConsoleOutput, pBuffer, bufferSize, bufferCoord, ref readRegion);
            }
            return ReadConsoleOutputUnicode(hConsoleOutput, pBuffer, bufferSize, bufferCoord, ref readRegion);
        }
    }
}
