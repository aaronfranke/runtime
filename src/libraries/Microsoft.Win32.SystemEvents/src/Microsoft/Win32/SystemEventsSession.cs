// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System;
using System.IO;
using System.Runtime.InteropServices;

namespace Microsoft.Win32
{
    internal static unsafe class SystemEventsSession
    {
        // Older Windows versions may have no WTS DLL or lack these notification
        // exports. Keep this optional provider lazy and load only the system DLL.
        private static readonly nint s_module = LoadModule();
        private static readonly delegate* unmanaged[Stdcall]<nint, int, int> s_register =
            (delegate* unmanaged[Stdcall]<nint, int, int>)GetEntryPoint("WTSRegisterSessionNotification");
        private static readonly delegate* unmanaged[Stdcall]<nint, int> s_unregister =
            (delegate* unmanaged[Stdcall]<nint, int>)GetEntryPoint("WTSUnRegisterSessionNotification");

        internal static bool Register(nint window, int flags) => s_register != null && s_register(window, flags) != 0;

        internal static bool Unregister(nint window) => s_unregister != null && s_unregister(window) != 0;

        private static nint GetEntryPoint(string name) => s_module == 0 ? 0 : NativeLibrary.GetExport(s_module, name);

        private static nint LoadModule()
        {
            if (!NativeLibrary.TryLoad(Path.Combine(Environment.SystemDirectory, Interop.Libraries.Wtsapi32), out nint module))
            {
                return 0;
            }

            if (NativeLibrary.TryGetExport(module, "WTSRegisterSessionNotification", out _) &&
                NativeLibrary.TryGetExport(module, "WTSUnRegisterSessionNotification", out _))
            {
                // Keep the module loaded while the cached entry points can be used.
                return module;
            }

            NativeLibrary.Free(module);
            return 0;
        }
    }
}
