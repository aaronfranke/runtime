// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.IO;
using System.Runtime.InteropServices;

namespace System.Net.Http
{
    internal static partial class SystemProxyInfo
    {
        private static unsafe HttpWindowsProxy ConstructLegacyWindowsProxy()
        {
            // IE5 introduced per-connection settings. Use its ANSI API;
            // querying only INTERNET_OPTION_PROXY would lose PAC/WPAD flags.
            // This is an initialization snapshot: older NT lacks the
            // thread-agnostic notifications used by this handler.
            if (!NativeLibrary.TryLoad(Path.Combine(Environment.SystemDirectory, "wininet.dll"), out IntPtr library))
            {
                throw new PlatformNotSupportedException("Reading system proxy settings requires WinINet with Internet Explorer 5 or later. Specify a proxy explicitly or disable proxying.");
            }

            // The option's union includes FILETIME, even on x86_32. Its native
            // size/alignment is 12/4 on x86_32 and 16/8 on x86_64.
            int stride = IntPtr.Size == 8 ? 16 : 12;
            int valueOffset = IntPtr.Size == 8 ? 8 : 4;
            Span<byte> buffer = stackalloc byte[3 * stride];
            buffer.Clear();
            fixed (byte* options = buffer)
            {
                try
                {
                    if (!NativeLibrary.TryGetExport(library, "InternetQueryOptionA", out IntPtr address))
                    {
                        throw new PlatformNotSupportedException("Reading system proxy settings requires InternetQueryOptionA. Specify a proxy explicitly or disable proxying.");
                    }

                    *(uint*)options = 1; // INTERNET_PER_CONN_FLAGS (FLAGS_UI requires newer IE).
                    *(uint*)(options + stride) = 2; // INTERNET_PER_CONN_PROXY_SERVER.
                    *(uint*)(options + 2 * stride) = 3; // INTERNET_PER_CONN_PROXY_BYPASS.
                    LegacyProxyOptionList list = new LegacyProxyOptionList
                    {
                        Size = (uint)sizeof(LegacyProxyOptionList),
                        Count = 3,
                        Options = options
                    };
                    uint size = list.Size;
                    var query = (delegate* unmanaged[Stdcall]<IntPtr, uint, void*, uint*, int>)address;
                    if (query(IntPtr.Zero, 75 /* INTERNET_OPTION_PER_CONNECTION_OPTION */, &list, &size) == 0)
                    {
                        throw new PlatformNotSupportedException("Reading per-connection proxy settings requires WinINet with Internet Explorer 5 or later. Specify a proxy explicitly or disable proxying.");
                    }

                    uint flags = *(uint*)(options + valueOffset);
                    if ((flags & ~3u) != 0 || (flags & 3u) == 0)
                    {
                        // Do not silently replace configured PAC/WPAD with a direct connection.
                        // These require a separate discovery/script engine on NT 4.
                        throw new PlatformNotSupportedException("Automatic proxy discovery and configuration scripts are not supported on legacy Windows. Specify a proxy explicitly or disable proxying.");
                    }

                    string? proxy = (flags & 2u) != 0 ? Marshal.PtrToStringAnsi(*(IntPtr*)(options + stride + valueOffset)) : null;
                    string? bypass = Marshal.PtrToStringAnsi(*(IntPtr*)(options + 2 * stride + valueOffset));
                    return new HttpWindowsProxy(new WinInetProxyHelper(proxy, bypass));
                }
                finally
                {
                    // WinINet owns the allocation strategy; its contract requires GlobalFree.
                    for (int index = 1; index < 3; index++)
                    {
                        IntPtr value = *(IntPtr*)(options + index * stride + valueOffset);
                        if (value != IntPtr.Zero)
                        {
                            FreeLegacyProxyString(value);
                        }
                    }
                    NativeLibrary.Free(library);
                }
            }
        }

        [StructLayout(LayoutKind.Sequential)]
        private unsafe struct LegacyProxyOptionList
        {
            public uint Size;
            public IntPtr Connection;
            public uint Count;
            public uint Error;
            public void* Options;
        }

        [LibraryImport("kernel32.dll", EntryPoint = "GlobalFree")]
        private static partial IntPtr FreeLegacyProxyString(IntPtr value);
    }
}
