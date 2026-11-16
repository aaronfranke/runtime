// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.IO;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;

namespace System.Net.Http
{
    internal sealed partial class HttpConnectionPool
    {
        private static async ValueTask<Stream> ConnectToTcpHostLegacyWindowsAsync(DnsEndPoint endPoint, CancellationToken cancellationToken)
        {
            // ConnectEx starts with XP, but this backend's cancellation needs Vista's
            // CancelIoEx. Earlier NT can use nonblocking connect/select
            // without binding a completion port or canceling native overlapped I/O.
            IPAddress[] addresses = await Dns.GetHostAddressesAsync(endPoint.Host, cancellationToken).ConfigureAwait(false);
            SocketException? lastException = null;
            foreach (IPAddress address in addresses)
            {
                cancellationToken.ThrowIfCancellationRequested();
                if (address.AddressFamily == AddressFamily.InterNetworkV6 && !Socket.OSSupportsIPv6)
                {
                    continue;
                }

                Socket socket = new Socket(address.AddressFamily, SocketType.Stream, ProtocolType.Tcp);
                try
                {
                    socket.NoDelay = true;
                    socket.Blocking = false;
                    try
                    {
                        socket.Connect(new IPEndPoint(address, endPoint.Port));
                    }
                    catch (SocketException error) when (error.SocketErrorCode == SocketError.WouldBlock)
                    {
                        while (!socket.Poll(0, SelectMode.SelectWrite) && !socket.Poll(0, SelectMode.SelectError))
                        {
                            // Cancellation closes this owned socket only after all native calls
                            // return. Closing a blocking connect from another thread would need
                            // the unavailable CancelIoEx path, or race a reused socket handle.
                            await Task.Delay(25, cancellationToken).ConfigureAwait(false);
                        }

                        SocketError status = (SocketError)(int)socket.GetSocketOption(SocketOptionLevel.Socket, SocketOptionName.Error)!;
                        if (status != SocketError.Success)
                        {
                            throw new SocketException((int)status);
                        }
                        if (!socket.Connected)
                        {
                            throw new SocketException((int)SocketError.NotConnected);
                        }
                    }

                    cancellationToken.ThrowIfCancellationRequested();
                    return new LegacyWindowsSocketStream(socket);
                }
                catch (SocketException error)
                {
                    socket.Dispose();
                    cancellationToken.ThrowIfCancellationRequested();
                    lastException = error;
                }
                catch
                {
                    socket.Dispose();
                    throw;
                }
            }

            throw lastException ?? new SocketException((int)SocketError.AddressFamilyNotSupported);
        }
    }
}
