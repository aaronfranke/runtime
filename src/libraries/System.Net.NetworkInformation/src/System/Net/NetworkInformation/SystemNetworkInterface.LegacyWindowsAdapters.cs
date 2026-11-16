// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.Buffers.Binary;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Net.Sockets;
using System.Numerics;
using System.Runtime.InteropServices;

namespace System.Net.NetworkInformation
{
    internal sealed partial class SystemNetworkInterface
    {
        private static NetworkInterface[] GetLegacyNetworkInterfaces()
        {
            LegacyInterfaceRow[] interfaces = ReadLegacyIpHelperTable<LegacyInterfaceRow>("GetIfTable") ??
                throw new NetworkInformationException(ErrorNotSupported);
            LegacyAddressRow[] addressRows = ReadLegacyIpHelperTable<LegacyAddressRow>("GetIpAddrTable") ??
                throw new NetworkInformationException(ErrorNotSupported);

            Dictionary<uint, UnicastIPAddressInformationCollection> addressesByIndex = new();
            foreach (LegacyAddressRow row in addressRows)
            {
                if (!addressesByIndex.TryGetValue(row.Index, out UnicastIPAddressInformationCollection? addresses))
                {
                    addresses = new UnicastIPAddressInformationCollection();
                    addressesByIndex.Add(row.Index, addresses);
                }

                // Win98 reports an all-zero address for configured adapters without an address.
                if (row.Address != 0)
                {
                    addresses.InternalAdd(new LegacyUnicastAddress(row.Address, row.Mask));
                }
            }

            Dictionary<uint, LegacyAdapterConfiguration> configurations = ReadLegacyAdapterConfigurations();
            NetworkInterface[] result = new NetworkInterface[interfaces.Length];
            for (int i = 0; i < interfaces.Length; i++)
            {
                ref readonly LegacyInterfaceRow row = ref interfaces[i];
                configurations.TryGetValue(row.Index, out LegacyAdapterConfiguration? configuration);
                addressesByIndex.TryGetValue(row.Index, out UnicastIPAddressInformationCollection? addresses);
                result[i] = new LegacyNetworkInterface(in row, configuration, addresses);
            }

            return result;
        }

        private static unsafe Dictionary<uint, LegacyAdapterConfiguration> ReadLegacyAdapterConfigurations()
        {
            Dictionary<uint, LegacyAdapterConfiguration> configurations = new();

            // NT 4 has a GetAdaptersInfo stub. The interface tables still provide address and link data.
            if (!NativeLibrary.TryLoad(Path.Combine(Environment.SystemDirectory, Interop.Libraries.IpHlpApi), out nint module))
            {
                return configurations;
            }

            try
            {
                if (!NativeLibrary.TryGetExport(module, "GetAdaptersInfo", out nint export))
                {
                    return configurations;
                }

                var getAdaptersInfo = (delegate* unmanaged[Stdcall]<void*, uint*, uint>)export;
                uint size = 0;
                uint capacity = 0;
                uint error = getAdaptersInfo(null, &size);
                while (error == Interop.IpHlpApi.ERROR_BUFFER_OVERFLOW)
                {
                    if (size <= capacity || size < sizeof(LegacyAdapterInfo) || size > int.MaxValue)
                    {
                        throw new NetworkInformationException((int)Interop.IpHlpApi.ERROR_INVALID_DATA);
                    }

                    capacity = size;
                    byte[] buffer = new byte[(int)capacity];
                    fixed (byte* start = buffer)
                    {
                        error = getAdaptersInfo(start, &size);
                        if (error == Interop.IpHlpApi.ERROR_SUCCESS)
                        {
                            if (size > capacity)
                            {
                                throw new NetworkInformationException((int)Interop.IpHlpApi.ERROR_INVALID_DATA);
                            }

                            ReadLegacyAdapterConfigurations(start, size, configurations);
                            return configurations;
                        }
                    }
                }

                if (error is not (Interop.IpHlpApi.ERROR_SUCCESS or Interop.IpHlpApi.ERROR_NO_DATA or
                    Interop.IpHlpApi.ERROR_INVALID_FUNCTION or ErrorNotSupported))
                {
                    throw new NetworkInformationException((int)error);
                }

                return configurations;
            }
            finally
            {
                NativeLibrary.Free(module);
            }
        }

        private static unsafe void ReadLegacyAdapterConfigurations(byte* start, uint size,
            Dictionary<uint, LegacyAdapterConfiguration> configurations)
        {
            uint remaining = size / (uint)sizeof(LegacyAdapterInfo);
            for (LegacyAdapterInfo* adapter = (LegacyAdapterInfo*)start; adapter != null; adapter = adapter->Next)
            {
                if (remaining-- == 0 || !IsInAdapterBuffer(adapter, (uint)sizeof(LegacyAdapterInfo), start, size))
                {
                    throw new NetworkInformationException((int)Interop.IpHlpApi.ERROR_INVALID_DATA);
                }

                InternalIPAddressCollection gateways = new();
                ReadLegacyAddressList(&adapter->GatewayList, start, size, gateways);

                InternalIPAddressCollection dhcpServers = new();
                if (adapter->DhcpEnabled != 0)
                {
                    ReadLegacyAddressList(&adapter->DhcpServer, start, size, dhcpServers);
                }

                InternalIPAddressCollection winsServers = new();
                if (adapter->HaveWins != 0)
                {
                    ReadLegacyAddressList(&adapter->PrimaryWinsServer, start, size, winsServers);
                    ReadLegacyAddressList(&adapter->SecondaryWinsServer, start, size, winsServers);
                }

                configurations.TryAdd(adapter->Index, new LegacyAdapterConfiguration(
                    ReadLegacyAnsiString(adapter->AdapterName, 260),
                    adapter->DhcpEnabled != 0,
                    SystemGatewayIPAddressInformation.ToGatewayIpAddressInformationCollection(gateways),
                    dhcpServers, winsServers));
            }
        }

        private static unsafe void ReadLegacyAddressList(Interop.IpHlpApi.IP_ADDR_STRING* address, byte* start, uint size,
            InternalIPAddressCollection addresses)
        {
            uint remaining = size / (uint)sizeof(Interop.IpHlpApi.IP_ADDR_STRING);
            while (address != null)
            {
                if (remaining-- == 0 || !IsInAdapterBuffer(address, (uint)sizeof(Interop.IpHlpApi.IP_ADDR_STRING), start, size))
                {
                    throw new NetworkInformationException((int)Interop.IpHlpApi.ERROR_INVALID_DATA);
                }

                string value = ReadLegacyAnsiString(&address->IpAddress[0], 16);
                if (IPAddress.TryParse(value, out IPAddress? ipAddress) &&
                    ipAddress.AddressFamily == AddressFamily.InterNetwork && !ipAddress.Equals(IPAddress.Any))
                {
                    addresses.InternalAdd(ipAddress);
                }

                address = address->Next;
            }
        }

        private static unsafe bool IsInAdapterBuffer(void* value, uint length, byte* start, uint size) =>
            length <= size && unchecked((nuint)value - (nuint)start) <= size - length;

        private static unsafe string ReadLegacyAnsiString(byte* data, int length)
        {
            int terminator = new ReadOnlySpan<byte>(data, length).IndexOf((byte)0);
            return Marshal.PtrToStringAnsi((nint)data, terminator >= 0 ? terminator : length);
        }

        // IP_ADAPTER_INFO before its time_t lease fields, whose width varies with the Windows ABI.
        [StructLayout(LayoutKind.Sequential)]
        private unsafe struct LegacyAdapterInfo
        {
            public LegacyAdapterInfo* Next;
            private uint _comboIndex;
            public fixed byte AdapterName[260];
            private fixed byte _description[132];
            private uint _addressLength;
            private fixed byte _address[8];
            public uint Index;
            private uint _type;
            public uint DhcpEnabled;
            private Interop.IpHlpApi.IP_ADDR_STRING* _currentIpAddress;
            private Interop.IpHlpApi.IP_ADDR_STRING _ipAddressList;
            public Interop.IpHlpApi.IP_ADDR_STRING GatewayList;
            public Interop.IpHlpApi.IP_ADDR_STRING DhcpServer;
            public int HaveWins;
            public Interop.IpHlpApi.IP_ADDR_STRING PrimaryWinsServer;
            public Interop.IpHlpApi.IP_ADDR_STRING SecondaryWinsServer;
        }

        private sealed class LegacyAdapterConfiguration(string name, bool isDhcpEnabled,
            GatewayIPAddressInformationCollection gateways, IPAddressCollection dhcpServers, IPAddressCollection winsServers)
        {
            public string Name { get; } = name;
            public bool IsDhcpEnabled { get; } = isDhcpEnabled;
            public GatewayIPAddressInformationCollection Gateways { get; } = gateways;
            public IPAddressCollection DhcpServers { get; } = dhcpServers;
            public IPAddressCollection WinsServers { get; } = winsServers;
        }

        private sealed class LegacyNetworkInterface : NetworkInterface
        {
            private readonly uint _index;
            private readonly byte[] _physicalAddress;
            private readonly LegacyIPInterfaceProperties _properties;

            internal LegacyNetworkInterface(in LegacyInterfaceRow row, LegacyAdapterConfiguration? configuration,
                UnicastIPAddressInformationCollection? addresses)
            {
                Description = row.GetDescription();
                Id = !string.IsNullOrEmpty(configuration?.Name)
                    ? configuration.Name
                    : row.Index.ToString(CultureInfo.InvariantCulture);
                string name = row.GetName();
                Name = name.Length != 0 ? name : Description.Length != 0 ? Description : Id;
                _index = row.Index;
                _physicalAddress = row.GetPhysicalAddress();
                NetworkInterfaceType = row.Type;
                OperationalStatus = GetOperationalStatus(in row);
                Speed = row.Speed;
                _properties = new LegacyIPInterfaceProperties(in row, configuration, addresses);
            }

            public override string Id { get; }
            public override string Name { get; }
            public override string Description { get; }
            public override NetworkInterfaceType NetworkInterfaceType { get; }
            public override OperationalStatus OperationalStatus { get; }
            public override long Speed { get; }
            public override bool IsReceiveOnly => throw new PlatformNotSupportedException(SR.net_InformationUnavailableOnPlatform);
            public override bool SupportsMulticast => throw new PlatformNotSupportedException(SR.net_InformationUnavailableOnPlatform);

            public override PhysicalAddress GetPhysicalAddress() => new PhysicalAddress(_physicalAddress);
            public override IPInterfaceProperties GetIPProperties() => _properties;
            public override IPInterfaceStatistics GetIPStatistics() => new SystemIPInterfaceStatistics(GetLegacyInterfaceCounters(_index));
            public override IPv4InterfaceStatistics GetIPv4Statistics() => new SystemIPv4InterfaceStatistics(GetLegacyInterfaceCounters(_index));
            public override bool Supports(NetworkInterfaceComponent component) =>
                component == NetworkInterfaceComponent.IPv4 && _properties.HasIPv4;

            private static OperationalStatus GetOperationalStatus(in LegacyInterfaceRow row)
            {
                // NT 4 and Win98 can report unreachable even for a working Ethernet or loopback interface.
                if (!OperatingSystem.IsWindowsVersionAtLeast(5) && row.Status == LegacyOperationalStatus.Unreachable)
                {
                    return OperationalStatus.Unknown;
                }

                return row.Status switch
                {
                    LegacyOperationalStatus.Connected or LegacyOperationalStatus.Operational => OperationalStatus.Up,
                    LegacyOperationalStatus.Connecting => OperationalStatus.Dormant,
                    LegacyOperationalStatus.NonOperational or LegacyOperationalStatus.Unreachable or
                        LegacyOperationalStatus.Disconnected => OperationalStatus.Down,
                    _ => OperationalStatus.Unknown,
                };
            }
        }

        private sealed class LegacyIPInterfaceProperties : IPInterfaceProperties
        {
            private readonly LegacyAdapterConfiguration? _configuration;
            private readonly LegacyIPv4InterfaceProperties? _ipv4;

            internal LegacyIPInterfaceProperties(in LegacyInterfaceRow row, LegacyAdapterConfiguration? configuration,
                UnicastIPAddressInformationCollection? addresses)
            {
                if (configuration != null || addresses != null)
                {
                    _ipv4 = new LegacyIPv4InterfaceProperties(row.Index, row.Mtu, configuration);
                }

                _configuration = configuration;
                UnicastAddresses = addresses ?? new UnicastIPAddressInformationCollection();
            }

            internal bool HasIPv4 => _ipv4 != null;
            public override bool IsDnsEnabled => HostInformationPal.GetEnableDns();
            public override string DnsSuffix => throw new PlatformNotSupportedException(SR.net_InformationUnavailableOnPlatform);
            public override bool IsDynamicDnsEnabled => throw new PlatformNotSupportedException(SR.net_InformationUnavailableOnPlatform);
            public override UnicastIPAddressInformationCollection UnicastAddresses { get; }
            public override MulticastIPAddressInformationCollection MulticastAddresses =>
                throw new PlatformNotSupportedException(SR.net_InformationUnavailableOnPlatform);
            public override IPAddressInformationCollection AnycastAddresses => throw new PlatformNotSupportedException(SR.net_InformationUnavailableOnPlatform);
            public override IPAddressCollection DnsAddresses => throw new PlatformNotSupportedException(SR.net_InformationUnavailableOnPlatform);
            public override GatewayIPAddressInformationCollection GatewayAddresses => Configuration.Gateways;
            public override IPAddressCollection DhcpServerAddresses => Configuration.DhcpServers;
            public override IPAddressCollection WinsServersAddresses => Configuration.WinsServers;

            public override IPv4InterfaceProperties GetIPv4Properties() =>
                _ipv4 ?? throw new NetworkInformationException(SocketError.ProtocolNotSupported);
            public override IPv6InterfaceProperties GetIPv6Properties() =>
                throw new NetworkInformationException(SocketError.ProtocolNotSupported);

            private LegacyAdapterConfiguration Configuration =>
                _configuration ?? throw new PlatformNotSupportedException(SR.net_InformationUnavailableOnPlatform);
        }

        private sealed class LegacyIPv4InterfaceProperties(uint index, uint mtu, LegacyAdapterConfiguration? configuration) : IPv4InterfaceProperties
        {
            public override bool UsesWins => Configuration.WinsServers.Count != 0;
            public override bool IsDhcpEnabled => Configuration.IsDhcpEnabled;
            public override bool IsAutomaticPrivateAddressingActive => throw new PlatformNotSupportedException(SR.net_InformationUnavailableOnPlatform);
            public override bool IsAutomaticPrivateAddressingEnabled => throw new PlatformNotSupportedException(SR.net_InformationUnavailableOnPlatform);
            public override int Index => unchecked((int)index);
            public override bool IsForwardingEnabled => HostInformationPal.GetEnableRouting();
            public override int Mtu => unchecked((int)mtu);

            private LegacyAdapterConfiguration Configuration =>
                configuration ?? throw new PlatformNotSupportedException(SR.net_InformationUnavailableOnPlatform);
        }

        private sealed class LegacyUnicastAddress(uint address, uint mask) : UnicastIPAddressInformation
        {
            public override IPAddress Address { get; } = new IPAddress(address);
            public override IPAddress IPv4Mask { get; } = new IPAddress(mask);

            public override int PrefixLength
            {
                get
                {
                    int length = BitOperations.PopCount(mask);
                    if (length != BitOperations.LeadingZeroCount(~BinaryPrimitives.ReverseEndianness(mask)))
                    {
                        throw new NetworkInformationException((int)Interop.IpHlpApi.ERROR_INVALID_DATA);
                    }

                    return length;
                }
            }

            public override bool IsDnsEligible => throw new PlatformNotSupportedException(SR.net_InformationUnavailableOnPlatform);
            public override bool IsTransient => throw new PlatformNotSupportedException(SR.net_InformationUnavailableOnPlatform);
            public override long AddressPreferredLifetime => throw new PlatformNotSupportedException(SR.net_InformationUnavailableOnPlatform);
            public override long AddressValidLifetime => throw new PlatformNotSupportedException(SR.net_InformationUnavailableOnPlatform);
            public override long DhcpLeaseLifetime => throw new PlatformNotSupportedException(SR.net_InformationUnavailableOnPlatform);
            public override DuplicateAddressDetectionState DuplicateAddressDetectionState =>
                throw new PlatformNotSupportedException(SR.net_InformationUnavailableOnPlatform);
            public override PrefixOrigin PrefixOrigin => throw new PlatformNotSupportedException(SR.net_InformationUnavailableOnPlatform);
            public override SuffixOrigin SuffixOrigin => throw new PlatformNotSupportedException(SR.net_InformationUnavailableOnPlatform);
        }
    }
}
