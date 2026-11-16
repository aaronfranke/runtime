// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Threading.Tasks;

namespace System.Net.NetworkInformation
{
    internal sealed class SystemIPGlobalProperties : IPGlobalProperties
    {
        internal SystemIPGlobalProperties()
        {
        }

        /// Specifies the host name for the local computer.
        public override string HostName
        {
            get
            {
                if (!OperatingSystem.IsWindowsVersionAtLeast(4, 10))
                {
                    // NT 4 and Windows 95 lack a working GetNetworkParams.
                    return Dns.GetHostName();
                }

                return HostInformationPal.GetHostName();
            }
        }

        /// Specifies the domain in which the local computer is registered.
        public override string DomainName
        {
            get
            {
                return HostInformationPal.GetDomainName();
            }
        }

        ///
        /// The type of node.
        ///
        /// <remarks>
        /// The exact mechanism by which NetBIOS names are resolved to IP addresses
        /// depends on the node's configured NetBIOS Node Type. Broadcast - uses broadcast
        /// NetBIOS Name Queries for name registration and resolution.
        /// PeerToPeer - uses a NetBIOS name server (NBNS), such as Windows Internet
        /// Name Service (WINS), to resolve NetBIOS names.
        /// Mixed - uses Broadcast then PeerToPeer.
        /// Hybrid - uses PeerToPeer then Broadcast.
        /// </remarks>
        public override NetBiosNodeType NodeType
        {
            get
            {
                return (NetBiosNodeType)HostInformationPal.GetNodeType();
            }
        }

        /// Specifies the DHCP scope name.
        public override string DhcpScopeName
        {
            get
            {
                return HostInformationPal.GetScopeId();
            }
        }

        /// Specifies whether the local computer is acting as an WINS proxy.
        public override bool IsWinsProxy
        {
            get
            {
                return HostInformationPal.GetEnableProxy();
            }
        }

        public override TcpConnectionInformation[] GetActiveTcpConnections()
        {
            List<TcpConnectionInformation> list = new List<TcpConnectionInformation>();
            GetAllTcpConnections(list, null);
            return list.ToArray();
        }

        public override IPEndPoint[] GetActiveTcpListeners()
        {
            List<IPEndPoint> list = new List<IPEndPoint>();
            GetAllTcpConnections(null, list);
            return list.ToArray();
        }

        private static unsafe uint GetTcpTable(nint buffer, uint* size, bool order, AddressFamily family,
            Interop.IpHlpApi.TcpTableClass tableClass)
        {
            if (OperatingSystem.IsWindowsVersionAtLeast(6))
            {
                return Interop.IpHlpApi.GetExtendedTcpTable(buffer, size, order, (uint)family, tableClass, 0);
            }

            // GetTcpTable includes listeners and connections. The caller filters by TCP state.
            return GetLegacyTransportTable(buffer, size, order, family, (int)tableClass, "GetTcpTable", "GetExtendedTcpTable");
        }

        private static unsafe uint GetUdpTable(nint buffer, uint* size, bool order, AddressFamily family,
            Interop.IpHlpApi.UdpTableClass tableClass)
        {
            if (OperatingSystem.IsWindowsVersionAtLeast(6))
            {
                return Interop.IpHlpApi.GetExtendedUdpTable(buffer, size, order, (uint)family, tableClass, 0);
            }

            return GetLegacyTransportTable(buffer, size, order, family, (int)tableClass, "GetUdpTable", "GetExtendedUdpTable");
        }

        private static unsafe uint GetLegacyTransportTable(nint buffer, uint* size, bool order, AddressFamily family,
            int tableClass, string basicExport, string extendedExport)
        {
            const uint ERROR_NOT_SUPPORTED = 50;
            // NT 5 and Win9x cannot use the restricted DLL search flag. Windows 95 can lack IP Helper entirely.
            if (!NativeLibrary.TryLoad(Path.Combine(Environment.SystemDirectory, Interop.Libraries.IpHlpApi), out nint module))
            {
                return ERROR_NOT_SUPPORTED;
            }

            try
            {
                bool ipv4 = family == AddressFamily.InterNetwork;
                if (!NativeLibrary.TryGetExport(module, ipv4 ? basicExport : extendedExport, out nint export))
                {
                    return ERROR_NOT_SUPPORTED;
                }

                // The basic tables contain IPv4 rows. IPv6 needs the extended exports added in later NT 5 releases.
                int nativeOrder = order ? 1 : 0;
                if (ipv4)
                {
                    var getTable = (delegate* unmanaged[Stdcall]<nint, uint*, int, uint>)export;
                    return getTable(buffer, size, nativeOrder);
                }

                var getExtendedTable = (delegate* unmanaged[Stdcall]<nint, uint*, int, uint, int, uint, uint>)export;
                return getExtendedTable(buffer, size, nativeOrder, (uint)family, tableClass, 0);
            }
            finally
            {
                NativeLibrary.Free(module);
            }
        }

        /// Gets the active TCP connections.
        private static unsafe void GetAllTcpConnections(List<TcpConnectionInformation>? connections, List<IPEndPoint>? listening)
        {
            uint size = 0;
            uint result;

            // Check if it supports IPv4 for IPv6 only modes.
            if (Socket.OSSupportsIPv4)
            {
                // Get the buffer size needed.
                result = GetTcpTable(0, &size, order: true, AddressFamily.InterNetwork,
                    connections is null ? Interop.IpHlpApi.TcpTableClass.TcpTableBasicListener : Interop.IpHlpApi.TcpTableClass.TcpTableBasicAll);

                while (result == Interop.IpHlpApi.ERROR_INSUFFICIENT_BUFFER)
                {
                    // Allocate the buffer and get the TCP table.
                    IntPtr buffer = Marshal.AllocHGlobal((int)size);
                    try
                    {
                        result = GetTcpTable(buffer, &size, order: true, AddressFamily.InterNetwork,
                            connections is null ? Interop.IpHlpApi.TcpTableClass.TcpTableBasicListener : Interop.IpHlpApi.TcpTableClass.TcpTableBasicAll);

                        if (result == Interop.IpHlpApi.ERROR_SUCCESS)
                        {
                            var table = (Interop.IpHlpApi.MibTcpTable*)buffer;
                            if (table->NumEntries > 0)
                            {
                                var span = new ReadOnlySpan<Interop.IpHlpApi.MibTcpRow>(&table->FirstEntry, (int)table->NumEntries);
                                Debug.Assert(sizeof(uint) + sizeof(Interop.IpHlpApi.MibTcpRow) * span.Length <= size);
                                foreach (ref readonly Interop.IpHlpApi.MibTcpRow entry in span)
                                {
                                    if (entry.State == TcpState.Listen)
                                    {
                                        listening?.Add(entry.LocalEndPoint);
                                    }
                                    else
                                    {
                                        connections?.Add(new SystemTcpConnectionInformation(in entry));
                                    }
                                }
                            }
                        }
                    }
                    finally
                    {
                        Marshal.FreeHGlobal(buffer);
                    }
                }

                // If we don't have any ipv4 interfaces detected, just continue.
                if (result != Interop.IpHlpApi.ERROR_SUCCESS && result != Interop.IpHlpApi.ERROR_NO_DATA)
                {
                    throw new NetworkInformationException((int)result);
                }
            }

            if (Socket.OSSupportsIPv6)
            {
                // Get the buffer size needed.
                size = 0;
                result = GetTcpTable(0, &size, order: true, AddressFamily.InterNetworkV6,
                    connections is null ? Interop.IpHlpApi.TcpTableClass.TcpTableOwnerPidListener : Interop.IpHlpApi.TcpTableClass.TcpTableOwnerPidAll);

                while (result == Interop.IpHlpApi.ERROR_INSUFFICIENT_BUFFER)
                {
                    // Allocate the buffer and get the TCP table.
                    IntPtr buffer = Marshal.AllocHGlobal((int)size);
                    try
                    {
                        result = GetTcpTable(buffer, &size, order: true, AddressFamily.InterNetworkV6,
                            connections is null ? Interop.IpHlpApi.TcpTableClass.TcpTableOwnerPidListener : Interop.IpHlpApi.TcpTableClass.TcpTableOwnerPidAll);

                        if (result == Interop.IpHlpApi.ERROR_SUCCESS)
                        {
                            var table = (Interop.IpHlpApi.MibTcp6TableOwnerPid*)buffer;
                            if (table->NumEntries > 0)
                            {
                                var span = new ReadOnlySpan<Interop.IpHlpApi.MibTcp6RowOwnerPid>(&table->FirstEntry, (int)table->NumEntries);
                                Debug.Assert(sizeof(uint) + sizeof(Interop.IpHlpApi.MibTcp6RowOwnerPid) * span.Length <= size);
                                foreach (ref readonly Interop.IpHlpApi.MibTcp6RowOwnerPid entry in span)
                                {
                                    if (entry.State == TcpState.Listen)
                                    {
                                        listening?.Add(entry.LocalEndPoint);
                                    }
                                    else
                                    {
                                        connections?.Add(new SystemTcpConnectionInformation(in entry));
                                    }
                                }
                            }
                        }
                    }
                    finally
                    {
                        Marshal.FreeHGlobal(buffer);
                    }
                }

                // If we don't have any ipv6 interfaces detected, just continue.
                if (result != Interop.IpHlpApi.ERROR_SUCCESS && result != Interop.IpHlpApi.ERROR_NO_DATA)
                {
                    throw new NetworkInformationException((int)result);
                }
            }
        }

        /// Gets the active UDP listeners.
        public override unsafe IPEndPoint[] GetActiveUdpListeners()
        {
            uint size = 0;
            uint result;
            List<IPEndPoint> udpListeners = new List<IPEndPoint>();

            // Check if it support IPv4 for IPv6 only modes.
            if (Socket.OSSupportsIPv4)
            {
                // Get the buffer size needed.
                result = GetUdpTable(0, &size, order: true, AddressFamily.InterNetwork,
                    Interop.IpHlpApi.UdpTableClass.UdpTableBasic);

                while (result == Interop.IpHlpApi.ERROR_INSUFFICIENT_BUFFER)
                {
                    // Allocate the buffer and get the UDP table.
                    IntPtr buffer = Marshal.AllocHGlobal((int)size);
                    try
                    {
                        result = GetUdpTable(buffer, &size, order: true, AddressFamily.InterNetwork,
                            Interop.IpHlpApi.UdpTableClass.UdpTableBasic);

                        if (result == Interop.IpHlpApi.ERROR_SUCCESS)
                        {
                            var table = (Interop.IpHlpApi.MibUdpTable*)buffer;
                            if (table->NumEntries > 0)
                            {
                                var span = new ReadOnlySpan<Interop.IpHlpApi.MibUdpRow>(&table->FirstEntry, (int)table->NumEntries);
                                Debug.Assert(sizeof(uint) + sizeof(Interop.IpHlpApi.MibUdpRow) * span.Length <= size);
                                foreach (ref readonly Interop.IpHlpApi.MibUdpRow entry in span)
                                {
                                    udpListeners.Add(entry.LocalEndPoint);
                                }
                            }
                        }
                    }
                    finally
                    {
                        Marshal.FreeHGlobal(buffer);
                    }
                }

                // If we don't have any ipv4 interfaces detected, just continue.
                if (result != Interop.IpHlpApi.ERROR_SUCCESS && result != Interop.IpHlpApi.ERROR_NO_DATA)
                {
                    throw new NetworkInformationException((int)result);
                }
            }

            if (Socket.OSSupportsIPv6)
            {
                // Get the buffer size needed.
                size = 0;
                result = GetUdpTable(IntPtr.Zero, &size, order: true,
                                                                        AddressFamily.InterNetworkV6,
                                                                        Interop.IpHlpApi.UdpTableClass.UdpTableOwnerPid);
                while (result == Interop.IpHlpApi.ERROR_INSUFFICIENT_BUFFER)
                {
                    // Allocate the buffer and get the UDP table.
                    IntPtr buffer = Marshal.AllocHGlobal((int)size);
                    try
                    {
                        result = GetUdpTable(buffer, &size, order: true,
                                                                                AddressFamily.InterNetworkV6,
                                                                                Interop.IpHlpApi.UdpTableClass.UdpTableOwnerPid);

                        if (result == Interop.IpHlpApi.ERROR_SUCCESS)
                        {
                            var table = (Interop.IpHlpApi.MibUdp6TableOwnerPid*)buffer;
                            if (table->NumEntries > 0)
                            {
                                var span = new ReadOnlySpan<Interop.IpHlpApi.MibUdp6RowOwnerPid>(&table->FirstEntry, (int)table->NumEntries);
                                Debug.Assert(sizeof(uint) + sizeof(Interop.IpHlpApi.MibUdp6RowOwnerPid) * span.Length <= size);
                                foreach (ref readonly Interop.IpHlpApi.MibUdp6RowOwnerPid entry in span)
                                {
                                    udpListeners.Add(entry.LocalEndPoint);
                                }
                            }
                        }
                    }
                    finally
                    {
                        Marshal.FreeHGlobal(buffer);
                    }
                }
                // If we don't have any ipv6 interfaces detected, just continue.
                if (result != Interop.IpHlpApi.ERROR_SUCCESS && result != Interop.IpHlpApi.ERROR_NO_DATA)
                {
                    throw new NetworkInformationException((int)result);
                }
            }

            return udpListeners.ToArray();
        }

        public override IPGlobalStatistics GetIPv4GlobalStatistics()
        {
            return new SystemIPGlobalStatistics(AddressFamily.InterNetwork);
        }

        public override IPGlobalStatistics GetIPv6GlobalStatistics()
        {
            return new SystemIPGlobalStatistics(AddressFamily.InterNetworkV6);
        }

        public override TcpStatistics GetTcpIPv4Statistics()
        {
            return new SystemTcpStatistics(AddressFamily.InterNetwork);
        }

        public override TcpStatistics GetTcpIPv6Statistics()
        {
            return new SystemTcpStatistics(AddressFamily.InterNetworkV6);
        }

        public override UdpStatistics GetUdpIPv4Statistics()
        {
            return new SystemUdpStatistics(AddressFamily.InterNetwork);
        }

        public override UdpStatistics GetUdpIPv6Statistics()
        {
            return new SystemUdpStatistics(AddressFamily.InterNetworkV6);
        }

        public override IcmpV4Statistics GetIcmpV4Statistics()
        {
            return new SystemIcmpV4Statistics();
        }

        public override IcmpV6Statistics GetIcmpV6Statistics()
        {
            return new SystemIcmpV6Statistics();
        }

        public override IAsyncResult BeginGetUnicastAddresses(AsyncCallback? callback, object? state) =>
            TaskToAsyncResult.Begin(GetUnicastAddressesAsync(), callback, state);

        public override UnicastIPAddressInformationCollection EndGetUnicastAddresses(IAsyncResult asyncResult) =>
            TaskToAsyncResult.End<UnicastIPAddressInformationCollection>(asyncResult);

        public override UnicastIPAddressInformationCollection GetUnicastAddresses() =>
            GetUnicastAddressesAsync().GetAwaiter().GetResult();

        public override async Task<UnicastIPAddressInformationCollection> GetUnicastAddressesAsync()
        {
            // Wait for the address table to stabilize.
            var tcs = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            if (!TeredoHelper.UnsafeNotifyStableUnicastIpAddressTable(s => ((TaskCompletionSource)s).TrySetResult(), tcs))
            {
                await tcs.Task.ConfigureAwait(false);
            }

            // Get the address table.
            var addresses = new UnicastIPAddressInformationCollection();

            foreach (NetworkInterface ni in NetworkInterface.GetAllNetworkInterfaces())
            {
                foreach (UnicastIPAddressInformation address in ni.GetIPProperties().UnicastAddresses)
                {
                    if (!addresses.Contains(address))
                    {
                        addresses.InternalAdd(address);
                    }
                }
            }

            return addresses;
        }
    }
}
