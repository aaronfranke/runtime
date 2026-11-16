// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.Buffers.Binary;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Threading;
using Microsoft.Win32.SafeHandles;

using static Interop.Advapi32;

namespace System.Diagnostics
{
    internal static partial class NtProcessManager
    {
        private static readonly bool s_useLegacyPsapi = !ProcessManager.HasKernel32Export("K32EnumProcessModulesEx");

        private static bool EnumProcessModules(SafeProcessHandle process, IntPtr[]? modules, int size, out int needed) =>
            s_useLegacyPsapi ? LegacyPsapi.EnumProcessModules(process, modules, size, out needed) :
            Interop.Kernel32.EnumProcessModulesEx(process, modules, size, out needed, Interop.Kernel32.LIST_MODULES_ALL);

        private static unsafe ProcessModuleCollection GetToolhelpModules(int processId, bool firstModuleOnly)
        {
            using SafeProcessHandle process = ProcessManager.OpenProcess(processId,
                ProcessOptions.PROCESS_QUERY_INFORMATION | ProcessOptions.PROCESS_VM_READ, true);

            Interop.Kernel32.SnapshotFlags flags = Interop.Kernel32.SnapshotFlags.Module;
            if (firstModuleOnly)
            {
                flags |= Interop.Kernel32.SnapshotFlags.Process;
            }

            var modules = new ProcessModuleCollection(firstModuleOnly ? 1 : 16);
            nint snapshot;
            for (int attempt = 0; ; attempt++)
            {
                snapshot = Interop.Kernel32.CreateToolhelp32Snapshot(flags, unchecked((uint)processId));
                if (snapshot != -1)
                {
                    break;
                }

                int error = Marshal.GetLastPInvokeError();
                if (error != Interop.Errors.ERROR_BAD_LENGTH || attempt == 49)
                {
                    throw new Win32Exception(error);
                }

                Thread.Sleep(1);
            }

            try
            {
                // On Win9x a DLL loaded later can precede the executable in the module list.
                int? mainModuleId = firstModuleOnly ? FindToolhelpMainModuleId(snapshot, processId) : null;
                if (firstModuleOnly && !mainModuleId.HasValue)
                {
                    return modules;
                }

                ToolhelpModuleEntry entry = default;
                entry.Size = sizeof(ToolhelpModuleEntry);
                for (bool found = Module32First(snapshot, &entry); found; found = Module32Next(snapshot, &entry))
                {
                    entry.Size = sizeof(ToolhelpModuleEntry);
                    if (mainModuleId.HasValue && entry.ModuleId != mainModuleId.Value)
                    {
                        continue;
                    }

                    string path = Marshal.PtrToStringAnsi((nint)entry.Path) ?? string.Empty;
                    string name = Marshal.PtrToStringAnsi((nint)entry.Name) ?? string.Empty;
                    modules.Add(new ProcessModule(path, name)
                    {
                        BaseAddress = entry.BaseAddress,
                        ModuleMemorySize = entry.ImageSize,
                        EntryPointAddress = ReadToolhelpEntryPoint(process, entry.BaseAddress, entry.ImageSize),
                    });
                    if (firstModuleOnly)
                    {
                        return modules;
                    }
                }

                int error = Marshal.GetLastPInvokeError();
                if (error != Interop.Errors.ERROR_NO_MORE_FILES)
                {
                    throw new Win32Exception(error);
                }
            }
            finally
            {
                Interop.Kernel32.CloseHandle(snapshot);
            }

            return modules;
        }

        private static unsafe int? FindToolhelpMainModuleId(nint snapshot, int processId)
        {
            Interop.Kernel32.PROCESSENTRY32 entry = default;
            entry.dwSize = sizeof(Interop.Kernel32.PROCESSENTRY32);
            for (bool found = Interop.Kernel32.Process32First(snapshot, &entry); found;
                found = Interop.Kernel32.Process32Next(snapshot, &entry))
            {
                if (entry.th32ProcessID == processId)
                {
                    return entry.th32ModuleID;
                }
            }

            int error = Marshal.GetLastPInvokeError();
            if (error != Interop.Errors.ERROR_NO_MORE_FILES)
            {
                throw new Win32Exception(error);
            }

            return null;
        }

        private static unsafe nint ReadToolhelpEntryPoint(SafeProcessHandle process, nint imageBase, int imageSize)
        {
            // Win9x Tool Help supplies the image range. Read the entry point RVA from the loaded PE headers.
            const int DosHeaderSize = 64;
            const int EntryPointOffset = 40;
            const int PeHeaderSize = EntryPointOffset + sizeof(int);
            byte* header = stackalloc byte[DosHeaderSize];
            if (imageSize < DosHeaderSize || !ReadProcessMemory(process, imageBase, header, DosHeaderSize, out nuint read) ||
                read != DosHeaderSize || header[0] != 'M' || header[1] != 'Z')
            {
                return 0;
            }

            int peOffset = BinaryPrimitives.ReadInt32LittleEndian(new ReadOnlySpan<byte>(header + 0x3c, sizeof(int)));
            if (peOffset < DosHeaderSize || peOffset > imageSize - PeHeaderSize ||
                !ReadProcessMemory(process, imageBase + peOffset, header, PeHeaderSize, out read) || read != PeHeaderSize ||
                !new ReadOnlySpan<byte>(header, 4).SequenceEqual("PE\0\0"u8) ||
                BinaryPrimitives.ReadUInt16LittleEndian(new ReadOnlySpan<byte>(header + 20, sizeof(ushort))) < 20)
            {
                return 0;
            }

            int rva = BinaryPrimitives.ReadInt32LittleEndian(new ReadOnlySpan<byte>(header + EntryPointOffset, sizeof(int)));
            return rva > 0 && rva < imageSize ? imageBase + rva : 0;
        }

        [StructLayout(LayoutKind.Sequential)]
        private unsafe struct ToolhelpModuleEntry
        {
            internal int Size;
            internal int ModuleId;
            private uint _processId;
            private uint _globalUsage;
            private uint _processUsage;
            internal nint BaseAddress;
            internal int ImageSize;
            private nint _moduleHandle;
            internal fixed byte Name[256];
            internal fixed byte Path[Interop.Kernel32.MAX_PATH];
        }

        // The Windows 95 and 98 Tool Help module APIs have unsuffixed ANSI exports.
        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        [LibraryImport(Interop.Libraries.Kernel32, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static unsafe partial bool Module32First(nint snapshot, ToolhelpModuleEntry* entry);

        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        [LibraryImport(Interop.Libraries.Kernel32, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static unsafe partial bool Module32Next(nint snapshot, ToolhelpModuleEntry* entry);

        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        [LibraryImport(Interop.Libraries.Kernel32, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static unsafe partial bool ReadProcessMemory(SafeProcessHandle process, nint address, byte* buffer,
            nuint requested, out nuint read);

        private static partial class LegacyPsapi
        {
            // Windows 7 added the K32 exports. Earlier NT releases expose the module APIs through PSAPI.
            private const string Library = "psapi.dll";

            [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
            [LibraryImport(Library, SetLastError = true)]
            [return: MarshalAs(UnmanagedType.Bool)]
            internal static partial bool EnumProcessModules(SafeProcessHandle process, IntPtr[]? modules, int size, out int needed);

            [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
            [LibraryImport(Library, SetLastError = true)]
            [return: MarshalAs(UnmanagedType.Bool)]
            internal static partial bool GetModuleInformation(SafeProcessHandle process, IntPtr module,
                out Interop.Kernel32.NtModuleInfo info, int size);

            [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
            [LibraryImport(Library, EntryPoint = "GetModuleBaseNameW", SetLastError = true, StringMarshalling = StringMarshalling.Utf16)]
            internal static partial int GetModuleBaseName(SafeProcessHandle process, IntPtr module, [Out] char[] name, int size);

            [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
            [LibraryImport(Library, EntryPoint = "GetModuleFileNameExW", SetLastError = true, StringMarshalling = StringMarshalling.Utf16)]
            internal static partial int GetModuleFileNameEx(SafeProcessHandle process, IntPtr module, [Out] char[] path, int size);
        }
    }
}
