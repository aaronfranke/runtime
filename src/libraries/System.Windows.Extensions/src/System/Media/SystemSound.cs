// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.IO;
using System.Runtime.InteropServices;

namespace System.Media
{
    public class SystemSound
    {
        private readonly int _soundType;

        internal SystemSound(int soundType)
        {
            _soundType = soundType;
        }

        public void Play()
        {
            if (!OperatingSystem.IsWindowsVersionAtLeast(6))
            {
                LegacySystemSound.Play(_soundType);
                return;
            }

            Interop.User32.MessageBeep(_soundType);
        }

        private static unsafe class LegacySystemSound
        {
            // Pre-Vista loaders do not support restricted DLL search flags.
            // Keep the system module loaded while its entry point is cached.
            private static readonly nint s_module = NativeLibrary.Load(Path.Combine(Environment.SystemDirectory, Interop.Libraries.User32));
            private static readonly delegate* unmanaged[Stdcall]<int, int> s_messageBeep =
                (delegate* unmanaged[Stdcall]<int, int>)NativeLibrary.GetExport(s_module, "MessageBeep");

            internal static void Play(int soundType)
            {
                s_messageBeep(soundType);
            }
        }
    }
}
