// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System;
using System.Diagnostics;
using System.Runtime.InteropServices;

namespace Microsoft.Win32
{
    internal static unsafe partial class SystemEventsWindow
    {
        internal static bool UseAnsiWindows => Environment.OSVersion.Platform == PlatformID.Win32Windows;

        internal static short RegisterClass(ref Interop.User32.WNDCLASS windowClass)
        {
            if (!UseAnsiWindows)
            {
                return Interop.User32.RegisterClassW(ref windowClass);
            }

            // SystemEvents generates an ASCII class name and does not use a menu.
            // Win95/98 export RegisterClassW but implement it as an unsupported stub.
            Debug.Assert(windowClass.lpszMenuName == null);
            nint name = Marshal.StringToHGlobalAnsi(new string(windowClass.lpszClassName));
            try
            {
                Interop.User32.WNDCLASS ansiClass = windowClass;
                ansiClass.lpszClassName = (char*)name;
                return RegisterClassA(ref ansiClass);
            }
            finally
            {
                Marshal.FreeHGlobal(name);
            }
        }

        internal static nint CreateWindowEx(int exStyle, string className, string windowName, int style,
            int x, int y, int width, int height, nint parent, nint menu, nint instance, nint parameter)
        {
            if (!UseAnsiWindows)
            {
                return Interop.User32.CreateWindowExW(exStyle, className, windowName, style,
                    x, y, width, height, parent, menu, instance, parameter);
            }

            nint name = 0;
            nint title = 0;
            try
            {
                name = Marshal.StringToHGlobalAnsi(className);
                title = Marshal.StringToHGlobalAnsi(windowName);
                return CreateWindowExA(exStyle, name, title, style,
                    x, y, width, height, parent, menu, instance, parameter);
            }
            finally
            {
                Marshal.FreeHGlobal(title);
                Marshal.FreeHGlobal(name);
            }
        }

        internal static short UnregisterClass(string className, nint instance)
        {
            if (!UseAnsiWindows)
            {
                return Interop.User32.UnregisterClassW(className, instance);
            }

            nint name = Marshal.StringToHGlobalAnsi(className);
            try
            {
                return UnregisterClassA(name, instance);
            }
            finally
            {
                Marshal.FreeHGlobal(name);
            }
        }

        internal static int RegisterWindowMessage(string message)
        {
            if (!UseAnsiWindows)
            {
                return Interop.User32.RegisterWindowMessageW(message);
            }

            nint name = Marshal.StringToHGlobalAnsi(message);
            try
            {
                return RegisterWindowMessageA(name);
            }
            finally
            {
                Marshal.FreeHGlobal(name);
            }
        }

        internal static nint SendMessage(nint window, int message, nint wParam, nint lParam) =>
            UseAnsiWindows ? SendMessageA(window, message, wParam, lParam) : Interop.User32.SendMessageW(window, message, wParam, lParam);

        internal static int PostMessage(nint window, int message, nint wParam, nint lParam) =>
            UseAnsiWindows ? PostMessageA(window, message, wParam, lParam) : Interop.User32.PostMessageW(window, message, wParam, lParam);

        internal static int GetMessage(ref Interop.User32.MSG message, nint window, int minimum, int maximum) =>
            UseAnsiWindows ? GetMessageA(ref message, window, minimum, maximum) : Interop.User32.GetMessageW(ref message, window, minimum, maximum);

        internal static int DispatchMessage(ref Interop.User32.MSG message) =>
            UseAnsiWindows ? DispatchMessageA(ref message) : Interop.User32.DispatchMessageW(ref message);

        internal static nint DefWindowProc(nint window, int message, nint wParam, nint lParam) =>
            UseAnsiWindows ? DefWindowProcA(window, message, wParam, lParam) : Interop.User32.DefWindowProcW(window, message, wParam, lParam);

        internal static nint SetWindowLong(nint window, int index, nint value) =>
            UseAnsiWindows ? SetWindowLongA(window, index, value) : Interop.User32.SetWindowLongW(window, index, value);

        internal static nint SetClassLong(nint window, int index, nint value) =>
            UseAnsiWindows ? SetClassLongA(window, index, value) : Interop.User32.SetClassLongW(window, index, value);

        // The 9x AOT profiles bind these classic USER32 exports directly. This
        // also avoids restricted DLL-search flags unavailable on those loaders.
        [LibraryImport(Interop.Libraries.User32, SetLastError = true)]
        private static partial short RegisterClassA(ref Interop.User32.WNDCLASS windowClass);

        [LibraryImport(Interop.Libraries.User32, SetLastError = true)]
        private static partial nint CreateWindowExA(int exStyle, nint className, nint windowName, int style,
            int x, int y, int width, int height, nint parent, nint menu, nint instance, nint parameter);

        [LibraryImport(Interop.Libraries.User32, SetLastError = true)]
        private static partial short UnregisterClassA(nint className, nint instance);

        [LibraryImport(Interop.Libraries.User32)]
        private static partial int RegisterWindowMessageA(nint message);

        [LibraryImport(Interop.Libraries.User32)]
        private static partial nint SendMessageA(nint window, int message, nint wParam, nint lParam);

        [LibraryImport(Interop.Libraries.User32)]
        private static partial int PostMessageA(nint window, int message, nint wParam, nint lParam);

        [LibraryImport(Interop.Libraries.User32)]
        private static partial int GetMessageA(ref Interop.User32.MSG message, nint window, int minimum, int maximum);

        [LibraryImport(Interop.Libraries.User32)]
        private static partial int DispatchMessageA(ref Interop.User32.MSG message);

        [LibraryImport(Interop.Libraries.User32)]
        private static partial nint DefWindowProcA(nint window, int message, nint wParam, nint lParam);

        [LibraryImport(Interop.Libraries.User32)]
        private static partial nint SetWindowLongA(nint window, int index, nint value);

        [LibraryImport(Interop.Libraries.User32)]
        private static partial nint SetClassLongA(nint window, int index, nint value);
    }
}
