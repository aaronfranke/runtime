// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.Security;
using System.Threading;

namespace System.IO.IsolatedStorage
{
    internal static partial class Helper
    {
        public const string IsolatedStorageDirectoryName = "IsolatedStorage";

        internal static string GetDataDirectory(IsolatedStorageScope scope)
        {
            // This is the relevant special folder for the given scope plus IsolatedStorageDirectoryName.
            // It is meant to replicate the behavior of the VM ComIsolatedStorage::GetRootDir().

            // (note that Silverlight used "CoreIsolatedStorage" for a directory name and did not support machine scope)

            bool legacyWindows = OperatingSystem.IsWindows() && !OperatingSystem.IsWindowsVersionAtLeast(6);
            if (legacyWindows && IsMachine(scope) && !OperatingSystem.IsWindowsVersionAtLeast(5))
            {
                // Win9x lacks NT filesystem ACLs, and NT 4 lacks the well-known SID API
                // used to secure a new machine store.
                throw new PlatformNotSupportedException(SR.IsolatedStorage_PlatformNotSupported);
            }

            Environment.SpecialFolder specialFolder =
            IsMachine(scope) ? Environment.SpecialFolder.CommonApplicationData : // e.g. C:\ProgramData
            IsRoaming(scope) ? Environment.SpecialFolder.ApplicationData : // e.g. C:\Users\Joe\AppData\Roaming
            Environment.SpecialFolder.LocalApplicationData; // e.g. C:\Users\Joe\AppData\Local

            string dataDirectory = Environment.GetFolderPath(specialFolder, Environment.SpecialFolderOption.Create);
            if (dataDirectory.Length == 0)
            {
                // A missing folder must not turn the store root into a relative path.
                throw new IsolatedStorageException(SR.IsolatedStorage_Init);
            }

            dataDirectory = Path.Combine(dataDirectory, IsolatedStorageDirectoryName);

            return dataDirectory;
        }

        internal static string GetRandomDirectory(string rootDirectory, IsolatedStorageScope scope)
        {
            string? randomDirectory = GetExistingRandomDirectory(rootDirectory);
            if (string.IsNullOrEmpty(randomDirectory))
            {
                using (Mutex m = CreateMutexNotOwned(rootDirectory))
                {
                    if (!m.WaitOne())
                    {
                        throw new IsolatedStorageException(SR.IsolatedStorage_Init);
                    }

                    try
                    {
                        randomDirectory = GetExistingRandomDirectory(rootDirectory);
                        if (string.IsNullOrEmpty(randomDirectory))
                        {
                            // Someone else hasn't created the directory before we took the lock
                            randomDirectory = Path.Combine(rootDirectory, Path.GetRandomFileName(), Path.GetRandomFileName());
                            CreateDirectory(randomDirectory, scope);
                        }
                    }
                    finally
                    {
                        m.ReleaseMutex();
                    }
                }
            }

            return randomDirectory;
        }

        private static Mutex CreateMutexNotOwned(string pathName)
        {
            string name = IdentityHelper.GetStrongHashSuitableForObjectName(pathName);
            if (OperatingSystem.IsWindows() && Environment.OSVersion.Platform == PlatformID.Win32Windows)
            {
                // Win9x has a single namespace for named wait handles.
                return new Mutex(initiallyOwned: false, name: name);
            }

            try
            {
                return new Mutex(initiallyOwned: false, name: @"Global\" + name);
            }
            catch (DirectoryNotFoundException) when (OperatingSystem.IsWindows() && !OperatingSystem.IsWindowsVersionAtLeast(5))
            {
                // NT 4 Workstation rejects the Global selector. Keep using it where the kernel accepts it.
                return new Mutex(initiallyOwned: false, name: name);
            }
        }
    }
}
