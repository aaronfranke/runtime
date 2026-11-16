// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System;
using System.IO;
using System.Runtime.InteropServices;

internal static partial class Interop
{
    internal static partial class IpHlpApi
    {
        internal static unsafe uint GetNetworkParams(IntPtr pFixedInfo, uint* pOutBufLen)
        {
            if (OperatingSystem.IsWindowsVersionAtLeast(6))
            {
                return GetNetworkParamsWindows(pFixedInfo, pOutBufLen);
            }

            // The restricted system DLL search flag is unavailable on NT 4/5.
            // NT 4 can export GetNetworkParams as a stub.
            const uint ERROR_NOT_SUPPORTED = 50;
            if (!NativeLibrary.TryLoad(Path.Combine(Environment.SystemDirectory, Libraries.IpHlpApi), out nint module))
            {
                return ERROR_NOT_SUPPORTED;
            }

            try
            {
                if (!NativeLibrary.TryGetExport(module, "GetNetworkParams", out nint export))
                {
                    return ERROR_NOT_SUPPORTED;
                }

                var getNetworkParams = (delegate* unmanaged[Stdcall]<IntPtr, uint*, uint>)export;
                return getNetworkParams(pFixedInfo, pOutBufLen);
            }
            finally
            {
                NativeLibrary.Free(module);
            }
        }

        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        [LibraryImport(Interop.Libraries.IpHlpApi, EntryPoint = "GetNetworkParams")]
        private static unsafe partial uint GetNetworkParamsWindows(IntPtr pFixedInfo, uint* pOutBufLen);
    }
}
