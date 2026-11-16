// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Threading;

namespace System.Net
{
    internal static partial class DnsResolverPal
    {
        // Windows 2000's DnsQueryEx export predates the modern request/result contract.
        // Use the documented Windows 2000 query/free pair before Windows 8.
        private static readonly bool s_useLegacyDns = !OperatingSystem.IsWindowsVersionAtLeast(6, 2);

        [LibraryImport("dnsapi.dll", EntryPoint = "DnsQuery_W")]
        private static unsafe partial int DnsQueryLegacy(char* name, ushort type, uint options,
            uint* servers, out IntPtr records, IntPtr reserved);

        [LibraryImport("dnsapi.dll", EntryPoint = "DnsRecordListFree")]
        private static partial void DnsRecordListFree(IntPtr records, int freeType);

        private static unsafe DnsQueryRawResult DnsQueryLegacySync(IPEndPoint[] servers, string name,
            ushort queryType, CancellationToken cancellationToken)
        {
            // NT 4 lacks this provider. Ordinary Winsock name lookup remains separate.
            if (!OperatingSystem.IsWindowsVersionAtLeast(5))
            {
                throw new PlatformNotSupportedException();
            }

            cancellationToken.ThrowIfCancellationRequested();
            uint[]? serverList = null;
            if (servers.Length > 0)
            {
                // The legacy IP4_ARRAY accepts IPv4 DNS servers only. This does not restrict
                // querying AAAA records through an IPv4 server on Windows 2000 or XP.
                serverList = new uint[checked(servers.Length + 1)];
                serverList[0] = (uint)servers.Length;
                for (int i = 0; i < servers.Length; i++)
                {
                    if (servers[i].AddressFamily != AddressFamily.InterNetwork)
                    {
                        throw new PlatformNotSupportedException();
                    }
                    servers[i].Address.TryWriteBytes(MemoryMarshal.AsBytes(serverList.AsSpan(i + 1, 1)), out _);
                }
            }

            int status;
            IntPtr records;
            fixed (char* queryName = name)
            fixed (uint* serverAddresses = serverList)
            {
                // Windows 2000 rejects an explicit server list with STANDARD (error 87).
                // BYPASS_CACHE also keeps a cached answer from overriding that server selection.
                uint options = serverList is null ? 0u : 0x8u; // DNS_QUERY_BYPASS_CACHE
                status = DnsQueryLegacy(queryName, queryType, options, serverAddresses, out records, IntPtr.Zero);
            }
            try
            {
                // The old native call has no cancellation handle. Cancellation of an in-flight
                // query completes only after that call returns; do not free its buffers early.
                cancellationToken.ThrowIfCancellationRequested();
                return new DnsQueryRawResult(MapWindowsErrorToResponseCode(status), records, ExtractNegativeCacheTtl(records));
            }
            catch
            {
                if (records != IntPtr.Zero)
                {
                    DnsRecordListFree(records, Interop.Dnsapi.DnsFreeRecordList);
                }
                throw;
            }
        }

        private static void FreeDnsRecords(IntPtr records)
        {
            if (s_useLegacyDns)
            {
                // DnsFree is absent on Windows 2000, including its SP4 baseline.
                DnsRecordListFree(records, Interop.Dnsapi.DnsFreeRecordList);
            }
            else
            {
                Interop.Dnsapi.DnsFree(records, Interop.Dnsapi.DnsFreeRecordList);
            }
        }
    }
}
