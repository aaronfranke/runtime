// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace System.Security.Principal
{
    internal static class Win32
    {
        internal const int FALSE = 0;

        //
        // Wrapper around advapi32.LsaOpenPolicy
        //


        internal static SafeLsaPolicyHandle LsaOpenPolicy(
            string? systemName,
            Interop.Advapi32.PolicyRights rights)
        {

            Interop.OBJECT_ATTRIBUTES attributes = default;
            uint error = Interop.Advapi32.LsaOpenPolicy(systemName, ref attributes, (int)rights, out SafeLsaPolicyHandle policyHandle);
            if (error == 0)
            {
                return policyHandle;
            }

            policyHandle.Dispose();

            if (error == Interop.StatusOptions.STATUS_ACCESS_DENIED)
            {
                throw new UnauthorizedAccessException();
            }
            else if (error == Interop.StatusOptions.STATUS_INSUFFICIENT_RESOURCES ||
                      error == Interop.StatusOptions.STATUS_NO_MEMORY)
            {
                throw new OutOfMemoryException();
            }
            else
            {
                uint win32ErrorCode = Interop.Advapi32.LsaNtStatusToWinError(error);

                throw new Win32Exception(unchecked((int)win32ErrorCode));
            }
        }


        internal static byte[] ConvertIntPtrSidToByteArraySid(IntPtr binaryForm)
        {
            byte[] ResultSid;

            //
            // Verify the revision (just sanity, should never fail to be 1)
            //

            byte Revision = Marshal.ReadByte(binaryForm, 0);

            if (Revision != SecurityIdentifier.Revision)
            {
                throw new ArgumentException(SR.IdentityReference_InvalidSidRevision, nameof(binaryForm));
            }

            //
            // Need the subauthority count in order to figure out how many bytes to read
            //

            byte SubAuthorityCount = Marshal.ReadByte(binaryForm, 1);

            if (SubAuthorityCount < 0 ||
                SubAuthorityCount > SecurityIdentifier.MaxSubAuthorities)
            {
                throw new ArgumentException(SR.Format(SR.IdentityReference_InvalidNumberOfSubauthorities, SecurityIdentifier.MaxSubAuthorities), nameof(binaryForm));
            }

            //
            // Compute the size of the binary form of this SID and allocate the memory
            //

            int BinaryLength = 1 + 1 + 6 + SubAuthorityCount * 4;
            ResultSid = new byte[BinaryLength];

            //
            // Extract the data from the returned pointer
            //

            Marshal.Copy(binaryForm, ResultSid, 0, BinaryLength);

            return ResultSid;
        }

        //
        // Wrapper around advapi32.ConvertStringSidToSidW
        //


        internal static unsafe int CreateSidFromString(
            string stringSid,
            out byte[]? resultSid
            )
        {
            int ErrorCode;
            void* pSid = null;

            try
            {
                if (Interop.BOOL.FALSE == Interop.Advapi32.ConvertStringSidToSid(stringSid, out pSid))
                {
                    ErrorCode = Marshal.GetLastPInvokeError();
                    goto Error;
                }

                resultSid = ConvertIntPtrSidToByteArraySid((IntPtr)pSid);
            }
            finally
            {
                //
                // Now is a good time to get rid of the returned pointer
                //

                Marshal.FreeHGlobal((IntPtr)pSid);
            }

            //
            // Now invoke the SecurityIdentifier factory method to create the result
            //

            return Interop.Errors.ERROR_SUCCESS;

        Error:

            resultSid = null;
            return ErrorCode;
        }

        //
        // Wrapper around advapi32.CreateWellKnownSid
        //


        internal static int CreateWellKnownSid(
            WellKnownSidType sidType,
            SecurityIdentifier? domainSid,
            out byte[]? resultSid
            )
        {
            //
            // Passing an array as big as it can ever be is a small price to pay for
            // not having to P/Invoke twice (once to get the buffer, once to get the data)
            //

            if (!OperatingSystem.IsWindowsVersionAtLeast(6, 2))
            {
                // Older Windows exports are missing or support fewer SID types. Use their defined components.
                resultSid = CreateLegacyWellKnownSid(sidType, domainSid)?.BinaryForm;
                return resultSid == null ? Interop.Errors.ERROR_INVALID_PARAMETER : Interop.Errors.ERROR_SUCCESS;
            }

            uint length = (uint)SecurityIdentifier.MaxBinaryLength;
            resultSid = new byte[length];

            if (FALSE != Interop.Advapi32.CreateWellKnownSid((int)sidType, domainSid?.BinaryForm, resultSid, ref length))
            {
                return Interop.Errors.ERROR_SUCCESS;
            }
            else
            {
                resultSid = null;

                return Marshal.GetLastPInvokeError();
            }
        }

        //
        // Wrapper around advapi32.EqualDomainSid
        //


        internal static bool IsEqualDomainSid(SecurityIdentifier sid1, SecurityIdentifier sid2)
        {
            if (sid1 == null || sid2 == null)
            {
                return false;
            }
            else
            {
                if (!OperatingSystem.IsWindowsVersionAtLeast(6, 2))
                {
                    if (sid1.IdentifierAuthority == IdentifierAuthority.NTAuthority &&
                        sid1.SubAuthorityCount > 0 && sid1.GetSubAuthority(0) == 32)
                    {
                        return sid2.IdentifierAuthority == IdentifierAuthority.NTAuthority &&
                            sid2.SubAuthorityCount > 0 && sid2.GetSubAuthority(0) == 32;
                    }

                    return GetWindowsAccountDomainSid(sid1, out SecurityIdentifier? domain1) == Interop.Errors.ERROR_SUCCESS &&
                        GetWindowsAccountDomainSid(sid2, out SecurityIdentifier? domain2) == Interop.Errors.ERROR_SUCCESS &&
                        domain1 == domain2;
                }

                byte[] BinaryForm1 = new byte[sid1.BinaryLength];
                sid1.GetBinaryForm(BinaryForm1, 0);

                byte[] BinaryForm2 = new byte[sid2.BinaryLength];
                sid2.GetBinaryForm(BinaryForm2, 0);

                return (Interop.Advapi32.IsEqualDomainSid(BinaryForm1, BinaryForm2, out bool result) == FALSE ? false : result);
            }
        }

        //
        // Wrapper around avdapi32.GetWindowsAccountDomainSid
        //
        internal static int GetWindowsAccountDomainSid(
            SecurityIdentifier sid,
            out SecurityIdentifier? resultSid
            )
        {
            //
            // Passing an array as big as it can ever be is a small price to pay for
            // not having to P/Invoke twice (once to get the buffer, once to get the data)
            //

            if (!OperatingSystem.IsWindowsVersionAtLeast(6, 2))
            {
                // Account SIDs start with the domain authority and three domain subauthorities.
                resultSid = null;
                if (sid.IdentifierAuthority != IdentifierAuthority.NTAuthority ||
                    sid.SubAuthorityCount < 4 || sid.GetSubAuthority(0) != 21)
                {
                    return Interop.Errors.ERROR_NON_ACCOUNT_SID;
                }

                resultSid = new SecurityIdentifier(IdentifierAuthority.NTAuthority,
                    [21, sid.GetSubAuthority(1), sid.GetSubAuthority(2), sid.GetSubAuthority(3)]);
                return Interop.Errors.ERROR_SUCCESS;
            }

            byte[] BinaryForm = new byte[sid.BinaryLength];
            sid.GetBinaryForm(BinaryForm, 0);
            uint sidLength = (uint)SecurityIdentifier.MaxBinaryLength;
            byte[] resultSidBinary = new byte[sidLength];

            if (FALSE != Interop.Advapi32.GetWindowsAccountDomainSid(BinaryForm, resultSidBinary, ref sidLength))
            {
                resultSid = new SecurityIdentifier(resultSidBinary, 0);

                return Interop.Errors.ERROR_SUCCESS;
            }
            else
            {
                resultSid = null;

                return Marshal.GetLastPInvokeError();
            }
        }

        //
        // Wrapper around advapi32.IsWellKnownSid
        //


        internal static bool IsWellKnownSid(
            SecurityIdentifier sid,
            WellKnownSidType type
            )
        {
            if (!OperatingSystem.IsWindowsVersionAtLeast(6, 2))
            {
                if (type == WellKnownSidType.LogonIdsSid)
                {
                    return sid.IdentifierAuthority == IdentifierAuthority.NTAuthority &&
                        sid.SubAuthorityCount == 3 && sid.GetSubAuthority(0) == 5;
                }

                return sid == CreateLegacyWellKnownSid(type, sid.AccountDomainSid);
            }

            byte[] BinaryForm = new byte[sid.BinaryLength];
            sid.GetBinaryForm(BinaryForm, 0);

            if (FALSE == Interop.Advapi32.IsWellKnownSid(BinaryForm, (int)type))
            {
                return false;
            }
            else
            {
                return true;
            }
        }

        private static SecurityIdentifier? CreateLegacyWellKnownSid(WellKnownSidType type, SecurityIdentifier? domainSid)
        {
            int accountRid = type switch
            {
                WellKnownSidType.AccountAdministratorSid => 500,
                WellKnownSidType.AccountGuestSid => 501,
                WellKnownSidType.AccountKrbtgtSid => 502,
                WellKnownSidType.AccountDomainAdminsSid => 512,
                WellKnownSidType.AccountDomainUsersSid => 513,
                WellKnownSidType.AccountDomainGuestsSid => 514,
                WellKnownSidType.AccountComputersSid => 515,
                WellKnownSidType.AccountControllersSid => 516,
                WellKnownSidType.AccountCertAdminsSid => 517,
                WellKnownSidType.AccountSchemaAdminsSid => 518,
                WellKnownSidType.AccountEnterpriseAdminsSid => 519,
                WellKnownSidType.AccountPolicyAdminsSid => 520,
                WellKnownSidType.AccountRasAndIasServersSid => 553,
                WellKnownSidType.WinCacheablePrincipalsGroupSid => 571,
                WellKnownSidType.WinNonCacheablePrincipalsGroupSid => 572,
                WellKnownSidType.WinAccountReadonlyControllersSid => 521,
                WellKnownSidType.WinNewEnterpriseReadonlyControllersSid => 498,
                _ => -1
            };

            if (accountRid != -1)
            {
                if (domainSid == null || domainSid.IdentifierAuthority != IdentifierAuthority.NTAuthority ||
                    domainSid.SubAuthorityCount != 4 || domainSid.GetSubAuthority(0) != 21)
                {
                    return null;
                }

                return new SecurityIdentifier(IdentifierAuthority.NTAuthority,
                    [21, domainSid.GetSubAuthority(1), domainSid.GetSubAuthority(2), domainSid.GetSubAuthority(3), accountRid]);
            }

            // The first component is the identifier authority, followed by the subauthorities.
            ReadOnlySpan<int> parts = type switch
            {
                WellKnownSidType.NullSid => [0, 0],
                WellKnownSidType.WorldSid => [1, 0],
                WellKnownSidType.LocalSid => [2, 0],
                WellKnownSidType.CreatorOwnerSid => [3, 0],
                WellKnownSidType.CreatorGroupSid => [3, 1],
                WellKnownSidType.CreatorOwnerServerSid => [3, 2],
                WellKnownSidType.CreatorGroupServerSid => [3, 3],
                WellKnownSidType.NTAuthoritySid => [5],
                WellKnownSidType.DialupSid => [5, 1],
                WellKnownSidType.NetworkSid => [5, 2],
                WellKnownSidType.BatchSid => [5, 3],
                WellKnownSidType.InteractiveSid => [5, 4],
                WellKnownSidType.ServiceSid => [5, 6],
                WellKnownSidType.AnonymousSid => [5, 7],
                WellKnownSidType.ProxySid => [5, 8],
                WellKnownSidType.EnterpriseControllersSid => [5, 9],
                WellKnownSidType.SelfSid => [5, 10],
                WellKnownSidType.AuthenticatedUserSid => [5, 11],
                WellKnownSidType.RestrictedCodeSid => [5, 12],
                WellKnownSidType.TerminalServerSid => [5, 13],
                WellKnownSidType.RemoteLogonIdSid => [5, 14],
                WellKnownSidType.LocalSystemSid => [5, 18],
                WellKnownSidType.LocalServiceSid => [5, 19],
                WellKnownSidType.NetworkServiceSid => [5, 20],
                WellKnownSidType.BuiltinDomainSid => [5, 32],
                WellKnownSidType.BuiltinAdministratorsSid => [5, 32, 544],
                WellKnownSidType.BuiltinUsersSid => [5, 32, 545],
                WellKnownSidType.BuiltinGuestsSid => [5, 32, 546],
                WellKnownSidType.BuiltinPowerUsersSid => [5, 32, 547],
                WellKnownSidType.BuiltinAccountOperatorsSid => [5, 32, 548],
                WellKnownSidType.BuiltinSystemOperatorsSid => [5, 32, 549],
                WellKnownSidType.BuiltinPrintOperatorsSid => [5, 32, 550],
                WellKnownSidType.BuiltinBackupOperatorsSid => [5, 32, 551],
                WellKnownSidType.BuiltinReplicatorSid => [5, 32, 552],
                WellKnownSidType.BuiltinPreWindows2000CompatibleAccessSid => [5, 32, 554],
                WellKnownSidType.BuiltinRemoteDesktopUsersSid => [5, 32, 555],
                WellKnownSidType.BuiltinNetworkConfigurationOperatorsSid => [5, 32, 556],
                WellKnownSidType.NtlmAuthenticationSid => [5, 64, 10],
                WellKnownSidType.DigestAuthenticationSid => [5, 64, 21],
                WellKnownSidType.SChannelAuthenticationSid => [5, 64, 14],
                WellKnownSidType.ThisOrganizationSid => [5, 15],
                WellKnownSidType.OtherOrganizationSid => [5, 1000],
                WellKnownSidType.BuiltinIncomingForestTrustBuildersSid => [5, 32, 557],
                WellKnownSidType.BuiltinPerformanceMonitoringUsersSid => [5, 32, 558],
                WellKnownSidType.BuiltinPerformanceLoggingUsersSid => [5, 32, 559],
                WellKnownSidType.BuiltinAuthorizationAccessSid => [5, 32, 560],
                WellKnownSidType.WinBuiltinTerminalServerLicenseServersSid => [5, 32, 561],
                WellKnownSidType.WinBuiltinDCOMUsersSid => [5, 32, 562],
                WellKnownSidType.WinBuiltinIUsersSid => [5, 32, 568],
                WellKnownSidType.WinIUserSid => [5, 17],
                WellKnownSidType.WinBuiltinCryptoOperatorsSid => [5, 32, 569],
                WellKnownSidType.WinUntrustedLabelSid => [16, 0],
                WellKnownSidType.WinLowLabelSid => [16, 4096],
                WellKnownSidType.WinMediumLabelSid => [16, 8192],
                WellKnownSidType.WinHighLabelSid => [16, 12288],
                WellKnownSidType.WinSystemLabelSid => [16, 16384],
                WellKnownSidType.WinWriteRestrictedCodeSid => [5, 33],
                WellKnownSidType.WinCreatorOwnerRightsSid => [3, 4],
                WellKnownSidType.WinEnterpriseReadonlyControllersSid => [5, 22],
                WellKnownSidType.WinBuiltinEventLogReadersGroup => [5, 32, 573],
                WellKnownSidType.WinBuiltinCertSvcDComAccessGroup => [5, 32, 574],
                WellKnownSidType.WinMediumPlusLabelSid => [16, 8448],
                WellKnownSidType.WinConsoleLogonSid => [2, 1],
                WellKnownSidType.WinThisOrganizationCertificateSid => [5, 65, 1],
                WellKnownSidType.WinBuiltinAnyPackageSid => [15, 2, 1],
                WellKnownSidType.WinCapabilityInternetClientSid => [15, 3, 1],
                WellKnownSidType.WinCapabilityInternetClientServerSid => [15, 3, 2],
                WellKnownSidType.WinCapabilityPrivateNetworkClientServerSid => [15, 3, 3],
                WellKnownSidType.WinCapabilityPicturesLibrarySid => [15, 3, 4],
                WellKnownSidType.WinCapabilityVideosLibrarySid => [15, 3, 5],
                WellKnownSidType.WinCapabilityMusicLibrarySid => [15, 3, 6],
                WellKnownSidType.WinCapabilityDocumentsLibrarySid => [15, 3, 7],
                WellKnownSidType.WinCapabilitySharedUserCertificatesSid => [15, 3, 9],
                WellKnownSidType.WinCapabilityEnterpriseAuthenticationSid => [15, 3, 8],
                WellKnownSidType.WinCapabilityRemovableStorageSid => [15, 3, 10],
                _ => []
            };

            return parts.IsEmpty ? null : new SecurityIdentifier((IdentifierAuthority)parts[0], parts[1..]);
        }
    }
}
