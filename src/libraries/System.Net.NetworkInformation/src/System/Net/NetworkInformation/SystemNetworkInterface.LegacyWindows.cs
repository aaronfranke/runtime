// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.IO;
using System.Net.Sockets;
using System.Runtime.InteropServices;

namespace System.Net.NetworkInformation
{
    internal sealed partial class SystemNetworkInterface
    {
        private const int ErrorNotSupported = 50;
        private const uint IPv4Loopback = 0x0100007f; // 127.0.0.1 in network byte order on Windows.

        private static bool GetLegacyNetworkAvailability()
        {
            // NT 4 and Win9x IP Helper can report every interface as unreachable.
            // On NT 5 the IP Helper table reports usable operational states.
            if (OperatingSystem.IsWindowsVersionAtLeast(5) && ReadLegacyIpHelperTable<LegacyInterfaceRow>("GetIfTable") is { } interfaces)
            {
                foreach (LegacyInterfaceRow row in interfaces)
                {
                    if ((row.Status is LegacyOperationalStatus.Connected or LegacyOperationalStatus.Operational) &&
                        row.Type is not (NetworkInterfaceType.Loopback or NetworkInterfaceType.Tunnel))
                    {
                        return true;
                    }
                }

                return false;
            }

            return GetLegacyIPv4Availability();
        }

        private static unsafe bool GetLegacyIPv4Availability()
        {
            const int SIO_GET_INTERFACE_LIST = 0x4004747f;
            const uint IFF_UP = 1;
            const uint IFF_LOOPBACK = 4;

            using Socket socket = new(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
            byte[] buffer = new byte[32 * sizeof(LegacyInterfaceInfo)];
            int bytes;
            while (true)
            {
                try
                {
                    bytes = socket.IOControl(SIO_GET_INTERFACE_LIST, null, buffer);
                    break;
                }
                catch (SocketException error) when (error.SocketErrorCode == SocketError.Fault)
                {
                    // SIO_GET_INTERFACE_LIST signals an insufficient output buffer with WSAEFAULT.
                    buffer = new byte[checked(buffer.Length * 2)];
                }
            }

            if ((uint)bytes > (uint)buffer.Length || bytes % sizeof(LegacyInterfaceInfo) != 0)
            {
                throw new NetworkInformationException((int)Interop.IpHlpApi.ERROR_INVALID_DATA);
            }

            foreach (LegacyInterfaceInfo entry in MemoryMarshal.Cast<byte, LegacyInterfaceInfo>(buffer.AsSpan(0, bytes)))
            {
                if (entry.Family == (ushort)AddressFamily.InterNetwork && (entry.Flags & (IFF_UP | IFF_LOOPBACK)) == IFF_UP &&
                    entry.Address != 0 && (entry.Address & 0xff) != 127)
                {
                    return true;
                }
            }

            return false;
        }

        private static int GetLegacyLoopbackInterfaceIndex()
        {
            // Winsock's IPv4 interface records do not include interface indexes.
            LegacyAddressRow[] rows = ReadLegacyIpHelperTable<LegacyAddressRow>("GetIpAddrTable") ??
                throw new NetworkInformationException(ErrorNotSupported);
            foreach (LegacyAddressRow row in rows)
            {
                if (row.Address == IPv4Loopback && row.Index != 0)
                {
                    return unchecked((int)row.Index);
                }
            }

            throw new NetworkInformationException((int)Interop.IpHlpApi.ERROR_NOT_FOUND);
        }

        private static unsafe Interop.IpHlpApi.MibIfRow2 GetLegacyInterfaceCounters(uint index)
        {
            // GetIfEntry2 starts with Vista. GetIfEntry returns 32-bit counters.
            if (!NativeLibrary.TryLoad(Path.Combine(Environment.SystemDirectory, Interop.Libraries.IpHlpApi), out nint module))
            {
                throw new NetworkInformationException(ErrorNotSupported);
            }

            try
            {
                if (!NativeLibrary.TryGetExport(module, "GetIfEntry", out nint export))
                {
                    throw new NetworkInformationException(ErrorNotSupported);
                }

                var getIfEntry = (delegate* unmanaged[Stdcall]<LegacyInterfaceRow*, uint>)export;
                LegacyInterfaceRow row = new() { Index = index };
                uint error = getIfEntry(&row);
                if (error != Interop.IpHlpApi.ERROR_SUCCESS)
                {
                    throw new NetworkInformationException((int)error);
                }

                // Widen each native counter without interpreting the high bit as a sign bit.
                return new Interop.IpHlpApi.MibIfRow2
                {
                    inOctets = row.InOctets,
                    inUcastPkts = row.InUnicastPackets,
                    inNUcastPkts = row.InNonUnicastPackets,
                    inDiscards = row.InDiscards,
                    inErrors = row.InErrors,
                    inUnknownProtos = row.InUnknownProtocols,
                    outOctets = row.OutOctets,
                    outUcastPkts = row.OutUnicastPackets,
                    outNUcastPkts = row.OutNonUnicastPackets,
                    outDiscards = row.OutDiscards,
                    outErrors = row.OutErrors,
                    outQLen = row.OutQueueLength,
                };
            }
            finally
            {
                NativeLibrary.Free(module);
            }
        }

        private static unsafe TRow[]? ReadLegacyIpHelperTable<TRow>(string exportName) where TRow : unmanaged
        {
            // Pre-Vista Windows lacks LOAD_LIBRARY_SEARCH_SYSTEM32. Load the system DLL by absolute path.
            if (!NativeLibrary.TryLoad(Path.Combine(Environment.SystemDirectory, Interop.Libraries.IpHlpApi), out nint module))
            {
                return null;
            }

            try
            {
                if (!NativeLibrary.TryGetExport(module, exportName, out nint export))
                {
                    return null;
                }

                var getTable = (delegate* unmanaged[Stdcall]<void*, uint*, int, uint>)export;
                uint size = 0;
                uint capacity = 0;
                uint error = getTable(null, &size, 0);
                while (error == Interop.IpHlpApi.ERROR_INSUFFICIENT_BUFFER)
                {
                    if (size <= capacity || size < sizeof(uint) || size > int.MaxValue)
                    {
                        throw new NetworkInformationException((int)Interop.IpHlpApi.ERROR_INVALID_DATA);
                    }

                    capacity = size;
                    byte[] buffer = new byte[(int)capacity];
                    fixed (byte* pointer = buffer)
                    {
                        error = getTable(pointer, &size, 0);
                        if (error == Interop.IpHlpApi.ERROR_SUCCESS)
                        {
                            uint count = *(uint*)pointer;
                            if (size < sizeof(uint) || size > capacity || count > (size - sizeof(uint)) / (uint)sizeof(TRow))
                            {
                                throw new NetworkInformationException((int)Interop.IpHlpApi.ERROR_INVALID_DATA);
                            }

                            // Both MIB_IFTABLE and MIB_IPADDRTABLE start with a DWORD row count,
                            // followed by rows whose fields have at most 4-byte alignment.
                            return new ReadOnlySpan<TRow>(pointer + sizeof(uint), (int)count).ToArray();
                        }
                    }
                }

                return error switch
                {
                    Interop.IpHlpApi.ERROR_SUCCESS or Interop.IpHlpApi.ERROR_NO_DATA => Array.Empty<TRow>(),
                    ErrorNotSupported or Interop.IpHlpApi.ERROR_INVALID_FUNCTION => null,
                    _ => throw new NetworkInformationException((int)error)
                };
            }
            finally
            {
                NativeLibrary.Free(module);
            }
        }

        private enum LegacyOperationalStatus : uint
        {
            NonOperational = 0,
            Unreachable = 1,
            Disconnected = 2,
            Connecting = 3,
            Connected = 4,
            Operational = 5
        }

        // Only the fields used from each fixed-size native row are declared.
        [StructLayout(LayoutKind.Explicit, Size = 860)] // MIB_IFROW
        private unsafe struct LegacyInterfaceRow
        {
            [FieldOffset(0)] private fixed char _name[256];
            [FieldOffset(512)] public uint Index;
            [FieldOffset(516)] public NetworkInterfaceType Type;
            [FieldOffset(520)] public uint Mtu;
            [FieldOffset(524)] public uint Speed;
            [FieldOffset(528)] private uint _physicalAddressLength;
            [FieldOffset(532)] private fixed byte _physicalAddress[8];
            [FieldOffset(544)] public LegacyOperationalStatus Status;
            [FieldOffset(552)] public uint InOctets;
            [FieldOffset(556)] public uint InUnicastPackets;
            [FieldOffset(560)] public uint InNonUnicastPackets;
            [FieldOffset(564)] public uint InDiscards;
            [FieldOffset(568)] public uint InErrors;
            [FieldOffset(572)] public uint InUnknownProtocols;
            [FieldOffset(576)] public uint OutOctets;
            [FieldOffset(580)] public uint OutUnicastPackets;
            [FieldOffset(584)] public uint OutNonUnicastPackets;
            [FieldOffset(588)] public uint OutDiscards;
            [FieldOffset(592)] public uint OutErrors;
            [FieldOffset(596)] public uint OutQueueLength;
            [FieldOffset(600)] private uint _descriptionLength;
            [FieldOffset(604)] private fixed byte _description[256];

            public readonly string GetName()
            {
                fixed (char* start = _name)
                {
                    ReadOnlySpan<char> name = new ReadOnlySpan<char>(start, 256);
                    int terminator = name.IndexOf('\0');
                    return new string(terminator >= 0 ? name[..terminator] : name);
                }
            }

            public readonly byte[] GetPhysicalAddress()
            {
                fixed (byte* start = _physicalAddress)
                {
                    return new ReadOnlySpan<byte>(start, (int)Math.Min(_physicalAddressLength, 8)).ToArray();
                }
            }

            public readonly string GetDescription()
            {
                fixed (byte* start = _description)
                {
                    return ReadLegacyAnsiString(start, (int)Math.Min(_descriptionLength, 256));
                }
            }
        }

        [StructLayout(LayoutKind.Explicit, Size = 24)] // MIB_IPADDRROW
        private struct LegacyAddressRow
        {
            [FieldOffset(0)] public uint Address;
            [FieldOffset(4)] public uint Index;
            [FieldOffset(8)] public uint Mask;
        }

        [StructLayout(LayoutKind.Explicit, Size = 76)] // INTERFACE_INFO
        private struct LegacyInterfaceInfo
        {
            [FieldOffset(0)] public uint Flags;
            [FieldOffset(4)] public ushort Family;
            [FieldOffset(8)] public uint Address;
        }
    }
}
