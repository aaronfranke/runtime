// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System;
using System.IO;
using System.Runtime.InteropServices;

internal static partial class Interop
{
    internal static partial class WinMM
    {
        private static bool UseLegacyWave => !OperatingSystem.IsWindowsVersionAtLeast(6);

        private static unsafe class LegacyWave
        {
            // Older loaders lack the restricted DLL search flags. Keep the system
            // module loaded for the lifetime of these cached entry points.
            private static readonly nint s_module = NativeLibrary.Load(Path.Combine(Environment.SystemDirectory, Libraries.WinMM));

            // Windows 95 and 98 require the ANSI path entry points. Memory-backed
            // PlaySound passes the same binary WAVE data to either export.
            private static readonly bool s_useAnsi = Environment.OSVersion.Platform == PlatformID.Win32Windows;
            private static readonly delegate* unmanaged[Stdcall]<nint, nint, int, int> s_play =
                (delegate* unmanaged[Stdcall]<nint, nint, int, int>)NativeLibrary.GetExport(s_module, s_useAnsi ? "PlaySoundA" : "PlaySoundW");
            private static readonly delegate* unmanaged[Stdcall]<nint, nint, int, nint> s_open =
                (delegate* unmanaged[Stdcall]<nint, nint, int, nint>)NativeLibrary.GetExport(s_module, s_useAnsi ? "mmioOpenA" : "mmioOpenW");
            private static readonly delegate* unmanaged[Stdcall]<nint, MMCKINFO*, MMCKINFO*, int, int> s_descend =
                (delegate* unmanaged[Stdcall]<nint, MMCKINFO*, MMCKINFO*, int, int>)NativeLibrary.GetExport(s_module, "mmioDescend");
            private static readonly delegate* unmanaged[Stdcall]<nint, byte*, int, int> s_read =
                (delegate* unmanaged[Stdcall]<nint, byte*, int, int>)NativeLibrary.GetExport(s_module, "mmioRead");
            private static readonly delegate* unmanaged[Stdcall]<nint, MMCKINFO*, int, int> s_ascend =
                (delegate* unmanaged[Stdcall]<nint, MMCKINFO*, int, int>)NativeLibrary.GetExport(s_module, "mmioAscend");
            private static readonly delegate* unmanaged[Stdcall]<nint, int, int> s_close =
                (delegate* unmanaged[Stdcall]<nint, int, int>)NativeLibrary.GetExport(s_module, "mmioClose");

            private static readonly object s_playLock = new object();
            private static GCHandle s_asynchronousWave;

            internal static bool PlayFile(string path, nint module, int flags)
            {
                nint nativePath = AllocatePath(path);
                if (nativePath == 0)
                {
                    return false;
                }

                try
                {
                    if ((flags & SND_ASYNC) == 0)
                    {
                        return s_play(nativePath, module, flags) != 0;
                    }

                    lock (s_playLock)
                    {
                        bool played = s_play(nativePath, module, flags) != 0;
                        if (played)
                        {
                            ReplaceAsynchronousWave(default);
                        }

                        return played;
                    }
                }
                finally
                {
                    Marshal.FreeHGlobal(nativePath);
                }
            }

            internal static bool PlayMemory(byte[]? wave, nint module, int flags)
            {
                if (wave != null && (flags & SND_ASYNC) == 0)
                {
                    fixed (byte* data = wave)
                    {
                        return s_play((nint)data, module, flags) != 0;
                    }
                }

                lock (s_playLock)
                {
                    if (wave == null)
                    {
                        // Passing a null sound with no flags stops the current playback.
                        bool stopped = s_play(0, module, 0) != 0;
                        if (stopped)
                        {
                            ReplaceAsynchronousWave(default);
                        }

                        return stopped;
                    }

                    // WinMM can keep reading the buffer after an asynchronous start returns.
                    GCHandle next = GCHandle.Alloc(wave, GCHandleType.Pinned);
                    try
                    {
                        if (s_play(next.AddrOfPinnedObject(), module, flags) == 0)
                        {
                            return false;
                        }

                        ReplaceAsynchronousWave(next);
                        next = default;
                        return true;
                    }
                    finally
                    {
                        if (next.IsAllocated)
                        {
                            next.Free();
                        }
                    }
                }
            }

            private static void ReplaceAsynchronousWave(GCHandle wave)
            {
                if (s_asynchronousWave.IsAllocated)
                {
                    s_asynchronousWave.Free();
                }

                s_asynchronousWave = wave;
            }

            internal static nint Open(string path, nint info, int flags)
            {
                nint nativePath = AllocatePath(path);
                if (nativePath == 0)
                {
                    return 0;
                }

                try
                {
                    return s_open(nativePath, info, flags);
                }
                finally
                {
                    Marshal.FreeHGlobal(nativePath);
                }
            }

            internal static int Descend(nint handle, MMCKINFO* chunk, MMCKINFO* parent, int flags) => s_descend(handle, chunk, parent, flags);

            internal static int Read(nint handle, byte[] buffer, int count)
            {
                fixed (byte* data = buffer)
                {
                    return s_read(handle, data, count);
                }
            }

            internal static int Ascend(nint handle, MMCKINFO* chunk, int flags) => s_ascend(handle, chunk, flags);

            internal static int Close(nint handle, int flags) => s_close(handle, flags);

            private static nint AllocatePath(string path)
            {
                if (!s_useAnsi)
                {
                    return Marshal.StringToHGlobalUni(path);
                }

                nint encoded = Marshal.StringToHGlobalAnsi(path);
                if (string.Equals(path, Marshal.PtrToStringAnsi(encoded), StringComparison.Ordinal))
                {
                    return encoded;
                }

                // Avoid opening a different file after an ANSI replacement or best fit.
                Marshal.FreeHGlobal(encoded);
                return 0;
            }
        }
    }
}
