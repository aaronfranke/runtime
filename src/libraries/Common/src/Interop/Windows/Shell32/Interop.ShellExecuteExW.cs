// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System;
using System.IO;
using System.Runtime.InteropServices;

internal static partial class Interop
{
    internal static partial class Shell32
    {
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        internal unsafe struct SHELLEXECUTEINFO
        {
            public uint cbSize;
            public uint fMask;
            public IntPtr hwnd;
            public char* lpVerb;
            public char* lpFile;
            public char* lpParameters;
            public char* lpDirectory;
            public int nShow;
            public IntPtr hInstApp;
            public IntPtr lpIDList;
            public IntPtr lpClass;
            public IntPtr hkeyClass;
            public uint dwHotKey;
            // This is a union of hIcon and hMonitor
            public IntPtr hIconMonitor;
            public IntPtr hProcess;
        }

        internal const int SW_HIDE = 0;
        internal const int SW_SHOWNORMAL = 1;
        internal const int SW_SHOWMINIMIZED = 2;
        internal const int SW_SHOWMAXIMIZED = 3;

        internal const int SE_ERR_FNF = 2;
        internal const int SE_ERR_PNF = 3;
        internal const int SE_ERR_ACCESSDENIED = 5;
        internal const int SE_ERR_OOM = 8;
        internal const int SE_ERR_DLLNOTFOUND = 32;
        internal const int SE_ERR_SHARE = 26;
        internal const int SE_ERR_ASSOCINCOMPLETE = 27;
        internal const int SE_ERR_DDETIMEOUT = 28;
        internal const int SE_ERR_DDEFAIL = 29;
        internal const int SE_ERR_DDEBUSY = 30;
        internal const int SE_ERR_NOASSOC = 31;

        internal const uint SEE_MASK_FLAG_DDEWAIT = 0x00000100;
        internal const uint SEE_MASK_NOCLOSEPROCESS = 0x00000040;
        internal const uint SEE_MASK_FLAG_NO_UI = 0x00000400;

        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        [LibraryImport(Libraries.Shell32, EntryPoint = "ShellExecuteExW", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static unsafe partial bool ShellExecuteExWNative(SHELLEXECUTEINFO* info);

        internal static unsafe bool ShellExecuteExW(SHELLEXECUTEINFO* info)
        {
            if (OperatingSystem.IsWindowsVersionAtLeast(6, 2))
            {
                return ShellExecuteExWNative(info);
            }

            // Older Windows may lack the DLL search flags used by the normal import.
            if (!NativeLibrary.TryLoad(Path.Combine(Environment.SystemDirectory, Libraries.Shell32), out nint shell))
            {
                Marshal.SetLastPInvokeError(Errors.ERROR_DLL_NOT_FOUND);
                return false;
            }

            int lastError = 0;
            Span<nint> ansiFields = stackalloc nint[5];
            ansiFields.Clear();
            try
            {
                // Windows 95 lacks ShellExecuteExW. The Windows 98 SE export is a stub.
                bool ansi = Environment.OSVersion.Platform == PlatformID.Win32Windows;
                if (!NativeLibrary.TryGetExport(shell, ansi ? "ShellExecuteExA" : "ShellExecuteExW", out nint address))
                {
                    lastError = Errors.ERROR_CALL_NOT_IMPLEMENTED;
                    return false;
                }

                // SHELLEXECUTEINFOA and SHELLEXECUTEINFOW have the same pointer layout.
                SHELLEXECUTEINFO native = *info;
                if (ansi)
                {
                    ReadOnlySpan<nint> wideFields = [(nint)native.lpVerb, (nint)native.lpFile, (nint)native.lpParameters,
                        (nint)native.lpDirectory, native.lpClass];
                    for (int i = 0; i < wideFields.Length; i++)
                    {
                        if (wideFields[i] == 0)
                        {
                            continue;
                        }

                        char* text = (char*)wideFields[i];
                        // Windows 95 rejects WC_NO_BEST_FIT_CHARS. A round trip checks for loss.
                        int size = Kernel32.WideCharToMultiByte(Kernel32.CP_ACP, 0, text, -1, null, 0, null, null);
                        if (size == 0)
                        {
                            lastError = Errors.ERROR_NO_UNICODE_TRANSLATION;
                            return false;
                        }

                        ansiFields[i] = Marshal.AllocCoTaskMem(size);
                        if (Kernel32.WideCharToMultiByte(Kernel32.CP_ACP, 0, text, -1, (byte*)ansiFields[i], size, null, null) != size ||
                            !string.Equals(new string(text), Marshal.PtrToStringAnsi(ansiFields[i]), StringComparison.Ordinal))
                        {
                            lastError = Errors.ERROR_NO_UNICODE_TRANSLATION;
                            return false;
                        }
                    }
                    native.lpVerb = (char*)ansiFields[0];
                    native.lpFile = (char*)ansiFields[1];
                    native.lpParameters = (char*)ansiFields[2];
                    native.lpDirectory = (char*)ansiFields[3];
                    native.lpClass = ansiFields[4];
                }

                var shellExecute = (delegate* unmanaged[Stdcall]<SHELLEXECUTEINFO*, int>)address;
                Marshal.SetLastSystemError(0);
                bool result = shellExecute(&native) != 0;
                lastError = Marshal.GetLastSystemError();
                info->hInstApp = native.hInstApp;
                info->hProcess = native.hProcess;
                return result;
            }
            catch (OutOfMemoryException)
            {
                lastError = Errors.ERROR_NOT_ENOUGH_MEMORY;
                return false;
            }
            finally
            {
                foreach (nint field in ansiFields)
                {
                    if (field != 0)
                    {
                        Marshal.FreeCoTaskMem(field);
                    }
                }
                NativeLibrary.Free(shell);
                Marshal.SetLastPInvokeError(lastError);
            }
        }
    }
}
