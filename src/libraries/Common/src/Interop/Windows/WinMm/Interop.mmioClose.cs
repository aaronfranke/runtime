// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System;
using System.Runtime.InteropServices;

internal static partial class Interop
{
    internal static partial class WinMM
    {
        internal static int mmioClose(IntPtr hMIO, int flags) =>
            UseLegacyWave ? LegacyWave.Close(hMIO, flags) : MmioCloseWindows(hMIO, flags);

        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        [LibraryImport(Libraries.WinMM, EntryPoint = "mmioClose")]
        private static partial int MmioCloseWindows(IntPtr hMIO, int flags);
    }
}
