// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System;
using System.Runtime.InteropServices;

internal static partial class Interop
{
    internal static partial class WinMM
    {
        internal static unsafe int mmioAscend(IntPtr hMIO, MMCKINFO* lpck, int flags) =>
            UseLegacyWave ? LegacyWave.Ascend(hMIO, lpck, flags) : MmioAscendWindows(hMIO, lpck, flags);

        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        [LibraryImport(Libraries.WinMM, EntryPoint = "mmioAscend")]
        private static unsafe partial int MmioAscendWindows(IntPtr hMIO, MMCKINFO* lpck, int flags);
    }
}
