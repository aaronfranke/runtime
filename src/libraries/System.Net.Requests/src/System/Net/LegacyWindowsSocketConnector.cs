// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;

namespace System.Net
{
    internal static class LegacyWindowsSocketConnector
    {
        internal static async ValueTask ConnectAsync(Socket socket, IPAddress[] addresses, int port, CancellationToken cancellationToken)
        {
            // Pre-Vista Windows cannot use ConnectEx with this backend's CancelIoEx
            // cancellation path. NT 4 also lacks ConnectEx itself. Keep the
            // caller's socket, ServicePoint options and explicit local binding.
            bool blocking = socket.Blocking;
            SocketException? lastException = null;
            socket.Blocking = false;
            try
            {
                foreach (IPAddress address in addresses)
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    if (address.AddressFamily != socket.AddressFamily &&
                        !(address.AddressFamily == AddressFamily.InterNetwork &&
                          socket.AddressFamily == AddressFamily.InterNetworkV6 && socket.DualMode))
                    {
                        continue;
                    }

                    try
                    {
                        try
                        {
                            socket.Connect(new IPEndPoint(address, port));
                        }
                        catch (SocketException error) when (error.SocketErrorCode == SocketError.WouldBlock)
                        {
                            while (!socket.Poll(0, SelectMode.SelectWrite) && !socket.Poll(0, SelectMode.SelectError))
                            {
                                // No native call remains active while awaiting cancellation.
                                // The owning callback closes the socket after this method exits.
                                await Task.Delay(25, cancellationToken).ConfigureAwait(false);
                            }

                            // Observe completion before draining SO_ERROR so Socket clears its
                            // pending-connect state even when this address failed and we retry.
                            bool connected = socket.Connected;
                            SocketError status = (SocketError)(int)socket.GetSocketOption(SocketOptionLevel.Socket, SocketOptionName.Error)!;
                            if (status != SocketError.Success)
                            {
                                throw new SocketException((int)status);
                            }
                            if (!connected)
                            {
                                throw new SocketException((int)SocketError.NotConnected);
                            }
                        }

                        cancellationToken.ThrowIfCancellationRequested();
                        return;
                    }
                    catch (SocketException error)
                    {
                        cancellationToken.ThrowIfCancellationRequested();
                        lastException = error;
                    }
                }

                cancellationToken.ThrowIfCancellationRequested();
                throw lastException ?? new SocketException((int)SocketError.AddressFamilyNotSupported);
            }
            finally
            {
                socket.Blocking = blocking;
            }
        }
    }
}
