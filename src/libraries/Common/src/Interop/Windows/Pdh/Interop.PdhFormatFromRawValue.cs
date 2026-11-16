// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System;
using System.IO;
using System.Runtime.InteropServices;
using static Interop.Kernel32.PerformanceCounterOptions;

internal static partial class Interop
{
    internal static partial class Pdh
    {
        private static class LegacyPdh
        {
            internal static readonly nint FormatFromRawValue = LoadFormatFromRawValue();

            private static nint LoadFormatFromRawValue()
            {
                // Pre-Vista Windows lacks restricted DLL search flags. PDH is optional
                // on NT 4, so open the system DLL by its full path when it exists.
                if (!NativeLibrary.TryLoad(Path.Combine(Environment.SystemDirectory, Libraries.Pdh), out nint module))
                {
                    return 0;
                }

                if (NativeLibrary.TryGetExport(module, nameof(PdhFormatFromRawValue), out nint export))
                {
                    // Keep the module reference for the lifetime of the cached entry point.
                    return export;
                }

                NativeLibrary.Free(module);
                return 0;
            }
        }

        internal static unsafe bool TryLegacyFormatFromRawValue(uint counterType, uint format,
            ref long timeBase, ref PDH_RAW_COUNTER newValue, ref PDH_RAW_COUNTER oldValue,
            ref PDH_FMT_COUNTERVALUE formattedValue, out int result)
        {
            nint address = LegacyPdh.FormatFromRawValue;
            if (address == 0)
            {
                result = 0;
                return false;
            }

            var formatFromRawValue = (delegate* unmanaged[Stdcall]<uint, uint, long*, PDH_RAW_COUNTER*, PDH_RAW_COUNTER*, PDH_FMT_COUNTERVALUE*, int>)address;
            fixed (long* timeBasePointer = &timeBase)
            fixed (PDH_RAW_COUNTER* newValuePointer = &newValue, oldValuePointer = &oldValue)
            fixed (PDH_FMT_COUNTERVALUE* formattedValuePointer = &formattedValue)
            {
                result = formatFromRawValue(counterType, format, timeBasePointer, newValuePointer, oldValuePointer, formattedValuePointer);
            }

            return true;
        }

        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        [LibraryImport(Libraries.Pdh)]
        public static partial int PdhFormatFromRawValue(
            uint dwCounterType,
            uint dwFormat,
            ref long pTimeBase,
            ref Interop.Kernel32.PerformanceCounterOptions.PDH_RAW_COUNTER pRawValue1,
            ref Interop.Kernel32.PerformanceCounterOptions.PDH_RAW_COUNTER pRawValue2,
            ref Interop.Kernel32.PerformanceCounterOptions.PDH_FMT_COUNTERVALUE pFmtValue
        );
    }
}
