// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.Diagnostics;
using System.IO;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;

namespace System.Net
{
    // This stream exclusively owns its connected HTTP socket. Pre-Vista Windows
    // cannot cancel another thread's blocking call with CancelIoEx, and shutdown
    // does not interrupt an already pending receive. Keep calls nonblocking and
    // serialize them with disposal; wait only after releasing the gate.
    internal sealed class LegacyWindowsSocketStream : Stream
    {
        private readonly Socket _socket;
        private readonly object _gate = new();
        private bool _disposed;
        private int _readTimeout;
        private int _writeTimeout;

        internal LegacyWindowsSocketStream(Socket socket)
        {
            _socket = socket;
            RemoteEndPoint = socket.RemoteEndPoint as IPEndPoint;
            _readTimeout = socket.ReceiveTimeout == 0 ? Timeout.Infinite : socket.ReceiveTimeout;
            _writeTimeout = socket.SendTimeout == 0 ? Timeout.Infinite : socket.SendTimeout;
            socket.Blocking = false;
        }

        internal IPEndPoint? RemoteEndPoint { get; }
        public override bool CanRead => !Volatile.Read(ref _disposed);
        public override bool CanWrite => !Volatile.Read(ref _disposed);
        public override bool CanSeek => false;
        public override bool CanTimeout => true;
        public override long Length => throw new NotSupportedException();
        public override long Position
        {
            get => throw new NotSupportedException();
            set => throw new NotSupportedException();
        }
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override int ReadTimeout
        {
            get => Volatile.Read(ref _readTimeout);
            set
            {
                ValidateTimeout(value);
                Volatile.Write(ref _readTimeout, value);
            }
        }
        public override int WriteTimeout
        {
            get => Volatile.Read(ref _writeTimeout);
            set
            {
                ValidateTimeout(value);
                Volatile.Write(ref _writeTimeout, value);
            }
        }

        private static void ValidateTimeout(int value)
        {
            if (value != Timeout.Infinite && value <= 0)
            {
                throw new ArgumentOutOfRangeException(nameof(value));
            }
        }

        private static IOException IoError(SocketException error) => new IOException(error.Message, error);

        private static void CheckTimeout(long start, int timeout)
        {
            if (timeout != Timeout.Infinite && Stopwatch.GetElapsedTime(start).TotalMilliseconds >= timeout)
            {
                throw IoError(new SocketException((int)SocketError.TimedOut));
            }
        }

        private int TryRead(Span<byte> buffer)
        {
            lock (_gate)
            {
                ObjectDisposedException.ThrowIf(_disposed, this);
                try
                {
                    if (buffer.IsEmpty)
                    {
                        // A zero-byte read waits for readiness without consuming data.
                        // Never keep a SafeHandle reference across the retry wait.
                        return _socket.Poll(0, SelectMode.SelectRead) ? 0 : -1;
                    }
                    return _socket.Receive(buffer, SocketFlags.None);
                }
                catch (SocketException error) when (error.SocketErrorCode == SocketError.WouldBlock)
                {
                    return -1;
                }
                catch (SocketException error)
                {
                    throw IoError(error);
                }
            }
        }

        private int TryWrite(ReadOnlySpan<byte> buffer)
        {
            lock (_gate)
            {
                ObjectDisposedException.ThrowIf(_disposed, this);
                if (buffer.IsEmpty)
                {
                    return 0;
                }
                try
                {
                    int sent = _socket.Send(buffer.Slice(0, Math.Min(buffer.Length, 16384)), SocketFlags.None);
                    if (sent == 0)
                    {
                        throw new IOException("The connection did not accept any data.");
                    }
                    return sent;
                }
                catch (SocketException error) when (error.SocketErrorCode == SocketError.WouldBlock)
                {
                    return -1;
                }
                catch (SocketException error)
                {
                    throw IoError(error);
                }
            }
        }

        public override int Read(byte[] buffer, int offset, int count)
        {
            ValidateBufferArguments(buffer, offset, count);
            return Read(buffer.AsSpan(offset, count));
        }

        public override int Read(Span<byte> buffer)
        {
            long start = Stopwatch.GetTimestamp();
            while (true)
            {
                int count = TryRead(buffer);
                if (count >= 0)
                {
                    return count;
                }
                CheckTimeout(start, ReadTimeout);
                Thread.Sleep(10);
            }
        }

        public override void Write(byte[] buffer, int offset, int count)
        {
            ValidateBufferArguments(buffer, offset, count);
            Write(buffer.AsSpan(offset, count));
        }

        public override void Write(ReadOnlySpan<byte> buffer)
        {
            long start = Stopwatch.GetTimestamp();
            do
            {
                int count = TryWrite(buffer);
                if (count >= 0)
                {
                    buffer = buffer.Slice(count);
                }
                else
                {
                    CheckTimeout(start, WriteTimeout);
                    Thread.Sleep(10);
                }
            } while (!buffer.IsEmpty);
        }

        public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
        {
            ValidateBufferArguments(buffer, offset, count);
            return ReadAsync(buffer.AsMemory(offset, count), cancellationToken).AsTask();
        }

        public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            while (true)
            {
                cancellationToken.ThrowIfCancellationRequested();
                int count = TryRead(buffer.Span);
                if (count >= 0)
                {
                    return count;
                }
                await Task.Delay(10, cancellationToken).ConfigureAwait(false);
            }
        }

        public override Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
        {
            ValidateBufferArguments(buffer, offset, count);
            return WriteAsync(buffer.AsMemory(offset, count), cancellationToken).AsTask();
        }

        public override async ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
        {
            do
            {
                cancellationToken.ThrowIfCancellationRequested();
                int count = TryWrite(buffer.Span);
                if (count >= 0)
                {
                    buffer = buffer.Slice(count);
                }
                else
                {
                    await Task.Delay(10, cancellationToken).ConfigureAwait(false);
                }
            } while (!buffer.IsEmpty);
        }

        public override void Flush()
        {
            ObjectDisposedException.ThrowIf(Volatile.Read(ref _disposed), this);
        }

        public override Task FlushAsync(CancellationToken cancellationToken)
        {
            if (cancellationToken.IsCancellationRequested)
            {
                return Task.FromCanceled(cancellationToken);
            }
            Flush();
            return Task.CompletedTask;
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                lock (_gate)
                {
                    if (!_disposed)
                    {
                        _disposed = true;
                        _socket.Dispose();
                    }
                }
            }
            base.Dispose(disposing);
        }
    }
}
