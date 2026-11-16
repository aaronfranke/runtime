// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

namespace System.Net.Http
{
    internal static partial class SystemProxyInfo
    {
        // On Windows we get default proxy configuration from either environment variables or the Windows system proxy.
        public static IWebProxy ConstructSystemProxy()
        {
            if (!HttpEnvironmentProxy.TryCreate(out IWebProxy? proxy))
            {
                // Modern Windows monitors settings; legacy Windows reads an initialization snapshot.
                proxy = OperatingSystem.IsWindowsVersionAtLeast(6) ? new HttpWindowsProxy() : ConstructLegacyWindowsProxy();
            }

            return proxy;
        }
    }
}
