// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Text;

namespace System.Net
{
    internal static partial class NameResolutionPal
    {
        private static class WinsockResolverSupport
        {
            private static readonly IntPtr s_module = GetWinsockModule();
            internal static readonly bool AddrInfo = HasExport("GetAddrInfoW") && HasExport("FreeAddrInfoW");
            internal static readonly bool NameInfo = HasExport("GetNameInfoW");

            // GetAddrInfoExCancel indicates that the OS supports overlapped resolution.
            internal static readonly bool AddrInfoEx = HasExport(Interop.Winsock.GetAddrInfoExCancelFunctionName);

            private static bool HasExport(string name) =>
                s_module != IntPtr.Zero && NativeLibrary.TryGetExport(s_module, name, out _);

            private static unsafe IntPtr GetWinsockModule()
            {
                Interop.Winsock.EnsureInitialized();
                // Winsock is already loaded; query that resident module.
                fixed (byte* name = "ws2_32.dll\0"u8)
                {
                    return GetModuleHandleA(name);
                }
            }
        }

        private static unsafe SocketError GetLegacyAddressInfo(string name, bool justAddresses, AddressFamily family,
            out string? hostName, out IPAddress[] addresses, out int nativeErrorCode)
        {
            hostName = name;
            addresses = Array.Empty<IPAddress>();
            if (family != AddressFamily.Unspecified && family != AddressFamily.InterNetwork)
            {
                nativeErrorCode = (int)SocketError.AddressFamilyNotSupported;
                return SocketError.AddressFamilyNotSupported;
            }
            if (!Ascii.IsValid(name))
            {
                // The legacy resolver takes ASCII DNS names, including already encoded IDNs.
                nativeErrorCode = (int)SocketError.HostNotFound;
                return SocketError.HostNotFound;
            }

            LegacyHostEntry* host = GetHostByName(name);
            if (host == null)
            {
                nativeErrorCode = Marshal.GetLastPInvokeError();
                return (SocketError)nativeErrorCode;
            }
            if (host->AddressFamily != (short)AddressFamily.InterNetwork || host->AddressLength != 4 ||
                host->Addresses == null || *host->Addresses == null)
            {
                nativeErrorCode = (int)SocketError.NoData;
                return SocketError.NoData;
            }

            // Winsock owns the host entry and can reuse it on the next call on this thread.
            int count = 0;
            while (host->Addresses[count] != null)
            {
                count++;
            }
            addresses = new IPAddress[count];
            for (int i = 0; i < count; i++)
            {
                addresses[i] = new IPAddress(new ReadOnlySpan<byte>(host->Addresses[i], 4));
            }
            hostName = justAddresses ? null : Marshal.PtrToStringAnsi((IntPtr)host->Name) ?? name;
            nativeErrorCode = 0;
            return SocketError.Success;
        }

        private static unsafe string? GetLegacyNameInfo(IPAddress address, out SocketError errorCode, out int nativeErrorCode)
        {
            if (address.AddressFamily != AddressFamily.InterNetwork)
            {
                errorCode = SocketError.AddressFamilyNotSupported;
                nativeErrorCode = (int)errorCode;
                return null;
            }
            byte* bytes = stackalloc byte[4];
            address.TryWriteBytes(new Span<byte>(bytes, 4), out _);
            LegacyHostEntry* host = GetHostByAddress(bytes, 4, AddressFamily.InterNetwork);
            if (host == null)
            {
                nativeErrorCode = Marshal.GetLastPInvokeError();
                errorCode = (SocketError)nativeErrorCode;
                return null;
            }

            string? name = Marshal.PtrToStringAnsi((IntPtr)host->Name);
            errorCode = string.IsNullOrEmpty(name) ? SocketError.NoData : SocketError.Success;
            nativeErrorCode = (int)errorCode;
            return name;
        }

        [StructLayout(LayoutKind.Sequential)]
        private unsafe struct LegacyHostEntry
        {
            internal byte* Name;
            internal byte** Aliases;
            internal short AddressFamily;
            internal short AddressLength;
            internal byte** Addresses;
        }

        [LibraryImport(Interop.Libraries.Kernel32)]
        private static unsafe partial IntPtr GetModuleHandleA(byte* name);

        [LibraryImport(Interop.Libraries.Ws2_32, EntryPoint = "gethostbyname", SetLastError = true,
            StringMarshalling = StringMarshalling.Utf8)]
        private static unsafe partial LegacyHostEntry* GetHostByName(string name);

        [LibraryImport(Interop.Libraries.Ws2_32, EntryPoint = "gethostbyaddr", SetLastError = true)]
        private static unsafe partial LegacyHostEntry* GetHostByAddress(byte* address, int length, AddressFamily family);
    }
}
