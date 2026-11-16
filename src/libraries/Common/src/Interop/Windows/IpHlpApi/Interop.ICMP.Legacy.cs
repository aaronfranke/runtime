// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Runtime.InteropServices.Marshalling;
using Microsoft.Win32.SafeHandles;

internal static partial class Interop
{
    internal static partial class IpHlpApi
    {
        internal sealed unsafe class LegacyIcmp
        {
            internal static LegacyIcmp? Instance { get; } =
                Load(Libraries.IpHlpApi, needsAsyncParser: true) ?? Load("icmp.dll", needsAsyncParser: true);

            private readonly delegate* unmanaged[Stdcall]<nint> _createFile;
            private readonly nint _closeHandle;
            private readonly delegate* unmanaged[Stdcall]<nint, uint, nint, ushort, IP_OPTION_INFORMATION*, nint, uint, uint, uint> _sendEcho;
            private readonly delegate* unmanaged[Stdcall]<nint, nint, nint, nint, uint, nint, ushort, IP_OPTION_INFORMATION*, nint, uint, uint, uint> _sendEcho2;
            private readonly delegate* unmanaged[Stdcall]<nint, uint, uint> _parseReplies;

            private LegacyIcmp(nint create, nint close, nint send, nint send2, nint parseReplies)
            {
                _createFile = (delegate* unmanaged[Stdcall]<nint>)create;
                _closeHandle = close;
                _parseReplies = (delegate* unmanaged[Stdcall]<nint, uint, uint>)parseReplies;
                _sendEcho = (delegate* unmanaged[Stdcall]<nint, uint, nint, ushort, IP_OPTION_INFORMATION*, nint, uint, uint, uint>)send;
                _sendEcho2 = (delegate* unmanaged[Stdcall]<nint, nint, nint, nint, uint, nint, ushort, IP_OPTION_INFORMATION*, nint, uint, uint, uint>)send2;
            }

            internal bool SupportsAsync => _sendEcho2 != null;
            internal bool RequiresAsyncParsing => _parseReplies != null;

            internal SafeCloseIcmpHandle CreateFile()
            {
                var result = new SafeCloseIcmpHandle(_closeHandle);
                Marshal.SetLastSystemError(0);
                nint handle = _createFile();
                int error = Marshal.GetLastSystemError();
                Marshal.InitHandle(result, handle);
                Marshal.SetLastPInvokeError(error);
                return result;
            }

            internal uint SendEcho(SafeCloseIcmpHandle icmpHandle, SafeWaitHandle waitHandle, bool isAsync, uint address,
                SafeLocalAllocHandle data, ushort dataSize, ref IP_OPTION_INFORMATION options,
                SafeLocalAllocHandle reply, uint replySize, uint timeout)
            {
                SafeHandleMarshaller<SafeCloseIcmpHandle>.ManagedToUnmanagedIn icmp = default;
                SafeHandleMarshaller<SafeWaitHandle>.ManagedToUnmanagedIn wait = default;
                SafeHandleMarshaller<SafeLocalAllocHandle>.ManagedToUnmanagedIn requestBuffer = default;
                SafeHandleMarshaller<SafeLocalAllocHandle>.ManagedToUnmanagedIn replyBuffer = default;
                uint result;
                int error;
                try
                {
                    icmp.FromManaged(icmpHandle);
                    requestBuffer.FromManaged(data);
                    replyBuffer.FromManaged(reply);
                    if (isAsync)
                    {
                        wait.FromManaged(waitHandle);
                    }

                    fixed (IP_OPTION_INFORMATION* optionsPointer = &options)
                    {
                        Marshal.SetLastSystemError(0);
                        result = isAsync
                            ? _sendEcho2(icmp.ToUnmanaged(), wait.ToUnmanaged(), 0, 0, address,
                                requestBuffer.ToUnmanaged(), dataSize, optionsPointer, replyBuffer.ToUnmanaged(), replySize, timeout)
                            : _sendEcho(icmp.ToUnmanaged(), address, requestBuffer.ToUnmanaged(), dataSize,
                                optionsPointer, replyBuffer.ToUnmanaged(), replySize, timeout);
                        error = Marshal.GetLastSystemError();
                    }
                }
                finally
                {
                    replyBuffer.Free();
                    requestBuffer.Free();
                    wait.Free();
                    icmp.Free();
                }

                Marshal.SetLastPInvokeError(error);
                return result;
            }

            internal uint ParseReplies(SafeLocalAllocHandle reply, uint size)
            {
                SafeHandleMarshaller<SafeLocalAllocHandle>.ManagedToUnmanagedIn replyBuffer = default;
                uint result;
                int error;
                try
                {
                    replyBuffer.FromManaged(reply);
                    Marshal.SetLastSystemError(0);
                    result = _parseReplies(replyBuffer.ToUnmanaged(), size);
                    error = Marshal.GetLastSystemError();
                }
                finally
                {
                    replyBuffer.Free();
                }

                Marshal.SetLastPInvokeError(error);
                return result;
            }

            private static LegacyIcmp? Load(string library, bool needsAsyncParser)
            {
                // Windows 2000 and earlier provide IPv4 echo in icmp.dll. XP and later
                // export it from IP Helper. Use the full system path on older loaders.
                if (!NativeLibrary.TryLoad(Path.Combine(Environment.SystemDirectory, library), out nint module))
                {
                    return null;
                }

                if (NativeLibrary.TryGetExport(module, nameof(IcmpCreateFile), out nint create) &&
                    NativeLibrary.TryGetExport(module, nameof(IcmpCloseHandle), out nint close) &&
                    NativeLibrary.TryGetExport(module, "IcmpSendEcho", out nint send))
                {
                    NativeLibrary.TryGetExport(module, nameof(IcmpSendEcho2), out nint send2);
                    // Keep the module reference for the lifetime of its cached entry points.
                    // NT 5 asynchronous replies need parsing in both icmp.dll and IP Helper.
                    nint parser = 0;
                    if (send2 != 0 && needsAsyncParser && !NativeLibrary.TryGetExport(module, "IcmpParseReplies", out parser))
                    {
                        send2 = 0;
                    }

                    return new LegacyIcmp(create, close, send, send2, parser);
                }

                NativeLibrary.Free(module);
                return null;
            }
        }
    }
}
