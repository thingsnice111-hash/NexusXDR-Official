using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;

namespace NexusAV.Engine;

public enum SignatureState { NotChecked, Unsigned, MicrosoftSigned, TrustedPublisher, Untrusted, Invalid }

public enum SignatureStatus { Unknown, Valid, Invalid, Unsigned, Untrusted }

/// <summary>
/// Authenticode verification through WinVerifyTrust. Two sources are consulted, because Windows
/// signs most inbox binaries through a catalog rather than embedding the signature: first the
/// file's own signature, then — only when no embedded signature exists — the catalog store
/// (CryptCATAdmin*). "isMicrosoftSigned" means the whole signer chain names Microsoft, not just
/// one subject string. Revocation is not consulted (see WTD_REVOKE_NONE below).
/// </summary>
public static unsafe partial class WinTrust
{
    public const uint WTD_UI_NONE = 2;
    public const uint WTD_REVOKE_NONE = 0;
    public const uint WTD_CHOICE_FILE = 1;
    public const uint WTD_CHOICE_CATALOG = 2;
    public const uint WTD_STATEACTION_VERIFY = 1;
    public const uint WTD_STATEACTION_CLOSE = 2;
    public const uint WTD_UICONTEXT_EXECUTE = 6;
    public const int  TRUST_E_NOSIGNATURE = unchecked((int)0x800B0100);
    public const int  TRUST_E_SUBJECT_NOT_TRUSTED = unchecked((int)0x800B0004);
    public const int  TRUST_E_PROVIDER_UNKNOWN = unchecked((int)0x800B0001);
    public const int  TRUST_E_SUBJECT_FORM_UNKNOWN = unchecked((int)0x800B0003);
    public const int  CRYPT_E_SECURITY_SETTINGS = unchecked((int)0x80092026);
    public const uint CERT_NAME_SIMPLE_DISPLAY_TYPE = 4;
    public const uint CRYPT_ASN_ENCODING = 0x00000001;
    public const uint X509_ASN_ENCODING = 0x00000001;
    public const int MAX_PATH = 260;
    public static readonly Guid DRIVER_ACTION_VERIFY = new Guid("{F750E6C3-38EE-11d1-85E5-00C04FC295EE}");
    public static readonly Guid WINTRUST_ACTION_GENERIC_VERIFY_V2 = new Guid("{00AAC56B-CD44-11d0-8CC2-00C04FC295EE}");

    [StructLayout(LayoutKind.Sequential)]
    public struct WINTRUST_FILE_INFO
    {
        public uint cbStruct;
        public IntPtr pcwszFilePath;
        public IntPtr hFile;
        public IntPtr pgKnownSubject;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct WINTRUST_CATALOG_INFO
    {
        public uint cbStruct;
        public uint dwCatalogVersion;
        public IntPtr pcwszCatalogFilePath;
        public IntPtr pcwszMemberTag;
        public IntPtr pcwszMemberFilePath;
        public IntPtr hMemberFile;
        public IntPtr pbCalculatedFileHash;
        public uint cbCalculatedFileHash;
        public IntPtr pcCatalogContext;
        public IntPtr hCatAdmin;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct WINTRUST_DATA
    {
        public uint cbStruct;
        public IntPtr pPolicyCallbackData;
        public IntPtr pSIPClientData;
        public uint dwUIChoice;
        public uint fdwRevocationChecks;
        public uint dwUnionChoice;
        public IntPtr pFile; // union: WINTRUST_FILE_INFO* / WINTRUST_CATALOG_INFO* / ...
        public uint dwStateAction;
        public IntPtr hWVTStateData;
        public IntPtr pwszURLReference;
        public uint dwProvFlags;
        public uint dwUIContext;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct CATALOG_INFO
    {
        public uint cbStruct;
        public fixed char wszCatalogFile[MAX_PATH];
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct FILETIME
    {
        public uint dwLowDateTime;
        public uint dwHighDateTime;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct CRYPT_PROVIDER_CERT
    {
        public uint cbStruct;
        public IntPtr pCert;
        public int fCommercial;
        public int fTrustedRoot;
        public int fSelfSigned;
        public int fTestCert;
        public uint dwRevokedReason;
        public uint dwConfidence;
        public uint dwError;
        public IntPtr pTrustListInfo;
        public int fHasRevocationFreshnessTime;
        public uint dwRevocationFreshnessTime;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct CRYPT_PROVIDER_SGNR
    {
        public uint cbStruct;
        public FILETIME sftVerifyAsOf;
        public uint csCertChain;
        public IntPtr pasCertChain;
        public uint dwSignerType;
        public IntPtr psSigner;
        public uint dwError;
        public uint csCounterSigners;
        public IntPtr pasCounterSigners;
        public IntPtr pChainContext;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct CRYPT_PROVIDER_DATA
    {
        public uint cbStruct;
        public IntPtr pWintrustData;
        public IntPtr pMsgAndCertEncodingType;
        public uint hProv;
        public uint hMsg;
        public uint csSigners;
        public uint csCounterSigners;
        public IntPtr ppSigner;
        public IntPtr pChainContext;
        public IntPtr pTrustStatus;
        public IntPtr pSIPData;
    }

    [LibraryImport("wintrust.dll")]
    public static partial int WinVerifyTrust(IntPtr hwnd, ref Guid pgActionID, ref WINTRUST_DATA pWVTData);

    [LibraryImport("crypt32.dll", SetLastError = true)]
    public static partial IntPtr CertCreateCertificateContext(uint dwCertEncodingType, byte* pbCertEncoded, uint cbCertEncoded);

    [LibraryImport("wintrust.dll", SetLastError = true)]
    public static partial IntPtr WTHelperProvDataFromStateData(IntPtr hStateData);

    [LibraryImport("wintrust.dll", SetLastError = true)]
    public static partial IntPtr WTHelperGetProvSignerFromChain(IntPtr pProvData, uint idxSigner, BOOL fCounterSigner, uint idxCounterSigner);

    [LibraryImport("crypt32.dll", EntryPoint = "CertGetNameStringW")]
    public static partial uint CertGetNameStringW(IntPtr pCertContext, uint dwType, uint dwFlags, IntPtr pvTypePara, char* pszNameString, uint cchNameString);

    [LibraryImport("wintrust.dll", SetLastError = true)]
    public static partial int CryptCATAdminAcquireContext2(out IntPtr phCatAdmin, IntPtr pgSubsystem, IntPtr pwszHashAlgorithm, IntPtr pStrongHashPolicy, uint dwFlags);

    [LibraryImport("wintrust.dll", SetLastError = true)]
    public static partial int CryptCATAdminCalcHashFromFileHandle2(IntPtr hCatAdmin, IntPtr hFile, ref uint pcbHash, byte* pbHash, uint dwFlags);

    [LibraryImport("wintrust.dll", SetLastError = true)]
    public static partial IntPtr CryptCATAdminEnumCatalogFromHash(IntPtr hCatAdmin, byte* pbHash, uint cbHash, uint dwFlags, ref IntPtr phPrevCatInfo);

    [LibraryImport("wintrust.dll", SetLastError = true)]
    public static partial int CryptCATCatalogInfoFromContext(IntPtr hCatInfo, ref CATALOG_INFO psCatInfo, uint dwFlags);

    [LibraryImport("wintrust.dll", SetLastError = true)]
    public static partial int CryptCATAdminReleaseCatalogContext(IntPtr hCatAdmin, IntPtr hCatInfo, uint dwFlags);

    [LibraryImport("wintrust.dll", SetLastError = true)]
    public static partial int CryptCATAdminReleaseContext(IntPtr hCatAdmin, uint dwFlags);

    public static (SignatureState state, bool isMicrosoftSigned) VerifyFile(string filePath)
    {
        if (string.IsNullOrEmpty(filePath) || !System.IO.File.Exists(filePath))
        {
            return (SignatureState.NotChecked, false);
        }

        try
        {
            (int status, bool isMs) = VerifyEmbedded(filePath);

            // No embedded signature: Windows signs most inbox binaries through a catalog, so the
            // file is not "unsigned" until the catalog store was consulted as well.
            if (status == TRUST_E_NOSIGNATURE || status == TRUST_E_SUBJECT_FORM_UNKNOWN || status == TRUST_E_PROVIDER_UNKNOWN)
            {
                (int catStatus, bool catMs) = VerifyCatalog(filePath);
                if (catStatus == 0)
                {
                    return (catMs ? SignatureState.MicrosoftSigned : SignatureState.TrustedPublisher, catMs);
                }
                return (SignatureState.Unsigned, false);
            }

            if (status == 0)
            {
                return (isMs ? SignatureState.MicrosoftSigned : SignatureState.TrustedPublisher, isMs);
            }

            return status == TRUST_E_SUBJECT_NOT_TRUSTED || status == CRYPT_E_SECURITY_SETTINGS
                ? (SignatureState.Untrusted, false)
                : (SignatureState.Invalid, false);
        }
        catch
        {
            return (SignatureState.NotChecked, false);
        }
    }

    private static (int status, bool isMicrosoft) VerifyEmbedded(string filePath)
    {
        IntPtr filePtr = Marshal.StringToHGlobalUni(filePath);
        IntPtr pFileInfo = IntPtr.Zero;
        try
        {
            WINTRUST_FILE_INFO fileInfo = new WINTRUST_FILE_INFO
            {
                cbStruct = (uint)Marshal.SizeOf<WINTRUST_FILE_INFO>(),
                pcwszFilePath = filePtr,
                hFile = IntPtr.Zero,
                pgKnownSubject = IntPtr.Zero
            };

            pFileInfo = Marshal.AllocHGlobal(Marshal.SizeOf<WINTRUST_FILE_INFO>());
            Marshal.StructureToPtr(fileInfo, pFileInfo, false);

            WINTRUST_DATA wtd = new WINTRUST_DATA
            {
                cbStruct = (uint)Marshal.SizeOf<WINTRUST_DATA>(),
                pPolicyCallbackData = IntPtr.Zero,
                pSIPClientData = IntPtr.Zero,
                dwUIChoice = WTD_UI_NONE,
                // Revocation is deliberately not consulted (WTD_REVOKE_NONE): a network lookup
                // per file would stall the scan. A certificate revoked after signing therefore
                // still verifies as Valid — WTD_REVOKE_WHOLECHAIN is the switch to flip if that
                // trade-off ever needs to change.
                fdwRevocationChecks = WTD_REVOKE_NONE,
                dwUnionChoice = WTD_CHOICE_FILE,
                pFile = pFileInfo,
                dwStateAction = WTD_STATEACTION_VERIFY,
                hWVTStateData = IntPtr.Zero,
                pwszURLReference = IntPtr.Zero,
                dwProvFlags = 0,
                dwUIContext = WTD_UICONTEXT_EXECUTE
            };

            Guid action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
            int status = WinVerifyTrust(IntPtr.Zero, ref action, ref wtd);
            bool isMicrosoft = status == 0 && IsMicrosoftSession(wtd.hWVTStateData);
            CloseState(wtd.hWVTStateData);
            return (status, isMicrosoft);
        }
        finally
        {
            if (pFileInfo != IntPtr.Zero) Marshal.FreeHGlobal(pFileInfo);
            Marshal.FreeHGlobal(filePtr);
        }
    }

    /// <summary>
    /// Looks the file's hash up in the catalog store and verifies the matching catalog. Returns
    /// TRUST_E_NOSIGNATURE when no catalog member covers this file.
    /// </summary>
    private static (int status, bool isMicrosoft) VerifyCatalog(string filePath)
    {
        IntPtr admin = IntPtr.Zero;
        IntPtr algorithm = IntPtr.Zero;
        try
        {
            algorithm = Marshal.StringToHGlobalUni("SHA256");
            if (CryptCATAdminAcquireContext2(out admin, IntPtr.Zero, algorithm, IntPtr.Zero, 0) == 0 || admin == IntPtr.Zero)
            {
                return (TRUST_E_NOSIGNATURE, false);
            }

            byte[] hash;
            try
            {
                using var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
                IntPtr hFile = fs.SafeFileHandle.DangerousGetHandle();

                uint size = 0;
                if (CryptCATAdminCalcHashFromFileHandle2(admin, hFile, ref size, null, 0) == 0 || size == 0 || size > 64)
                {
                    return (TRUST_E_NOSIGNATURE, false);
                }
                hash = new byte[size];
                fixed (byte* pHash = hash)
                {
                    uint got = size;
                    if (CryptCATAdminCalcHashFromFileHandle2(admin, hFile, ref got, pHash, 0) == 0 || got != size)
                    {
                        return (TRUST_E_NOSIGNATURE, false);
                    }
                }
            }
            catch
            {
                return (TRUST_E_NOSIGNATURE, false);
            }

            string memberTag = Convert.ToHexString(hash);
            int result = TRUST_E_NOSIGNATURE;
            bool resultIsMicrosoft = false;

            fixed (byte* pHash = hash)
            {
                IntPtr previous = IntPtr.Zero;
                while (true)
                {
                    IntPtr catalog = CryptCATAdminEnumCatalogFromHash(admin, pHash, (uint)hash.Length, 0, ref previous);
                    if (catalog == IntPtr.Zero) break;
                    previous = catalog;

                    try
                    {
                        CATALOG_INFO info = new CATALOG_INFO { cbStruct = (uint)Marshal.SizeOf<CATALOG_INFO>() };
                        if (CryptCATCatalogInfoFromContext(catalog, ref info, 0) != 0)
                        {
                            string catalogPath = ReadFixedString(info.wszCatalogFile, MAX_PATH);
                            if (catalogPath.Length > 0)
                            {
                                (int status, bool isMicrosoft) = VerifyCatalogMember(filePath, catalogPath, memberTag, hash, admin);
                                if (status == 0)
                                {
                                    result = 0;
                                    resultIsMicrosoft = isMicrosoft;
                                    break;
                                }
                            }
                        }
                    }
                    finally
                    {
                        CryptCATAdminReleaseCatalogContext(admin, catalog, 0);
                    }
                }
            }

            return (result, resultIsMicrosoft);
        }
        catch
        {
            return (TRUST_E_NOSIGNATURE, false);
        }
        finally
        {
            if (admin != IntPtr.Zero) CryptCATAdminReleaseContext(admin, 0);
            if (algorithm != IntPtr.Zero) Marshal.FreeHGlobal(algorithm);
        }
    }

    private static (int status, bool isMicrosoft) VerifyCatalogMember(string filePath, string catalogPath, string memberTag, byte[] hash, IntPtr admin)
    {
        IntPtr catPtr = IntPtr.Zero, tagPtr = IntPtr.Zero, filePtr = IntPtr.Zero, hashPtr = IntPtr.Zero, infoPtr = IntPtr.Zero;
        try
        {
            catPtr = Marshal.StringToHGlobalUni(catalogPath);
            tagPtr = Marshal.StringToHGlobalUni(memberTag);
            filePtr = Marshal.StringToHGlobalUni(filePath);
            hashPtr = Marshal.AllocHGlobal(hash.Length);
            Marshal.Copy(hash, 0, hashPtr, hash.Length);

            WINTRUST_CATALOG_INFO catInfo = new WINTRUST_CATALOG_INFO
            {
                cbStruct = (uint)Marshal.SizeOf<WINTRUST_CATALOG_INFO>(),
                dwCatalogVersion = 0,
                pcwszCatalogFilePath = catPtr,
                pcwszMemberTag = tagPtr,
                pcwszMemberFilePath = filePtr,
                hMemberFile = IntPtr.Zero,
                pbCalculatedFileHash = hashPtr,
                cbCalculatedFileHash = (uint)hash.Length,
                pcCatalogContext = IntPtr.Zero,
                hCatAdmin = admin
            };
            infoPtr = Marshal.AllocHGlobal(Marshal.SizeOf<WINTRUST_CATALOG_INFO>());
            Marshal.StructureToPtr(catInfo, infoPtr, false);

            WINTRUST_DATA wtd = new WINTRUST_DATA
            {
                cbStruct = (uint)Marshal.SizeOf<WINTRUST_DATA>(),
                dwUIChoice = WTD_UI_NONE,
                fdwRevocationChecks = WTD_REVOKE_NONE,
                dwUnionChoice = WTD_CHOICE_CATALOG,
                pFile = infoPtr, // union field: WINTRUST_CATALOG_INFO* lives at the pFile offset
                dwStateAction = WTD_STATEACTION_VERIFY,
                dwUIContext = WTD_UICONTEXT_EXECUTE
            };

            Guid action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
            int status = WinVerifyTrust(IntPtr.Zero, ref action, ref wtd);
            bool isMicrosoft = status == 0 && IsMicrosoftSession(wtd.hWVTStateData);
            CloseState(wtd.hWVTStateData);
            return (status, isMicrosoft);
        }
        catch
        {
            return (TRUST_E_NOSIGNATURE, false);
        }
        finally
        {
            if (infoPtr != IntPtr.Zero) Marshal.FreeHGlobal(infoPtr);
            if (hashPtr != IntPtr.Zero) Marshal.FreeHGlobal(hashPtr);
            if (filePtr != IntPtr.Zero) Marshal.FreeHGlobal(filePtr);
            if (tagPtr != IntPtr.Zero) Marshal.FreeHGlobal(tagPtr);
            if (catPtr != IntPtr.Zero) Marshal.FreeHGlobal(catPtr);
        }
    }

    private static void CloseState(IntPtr state)
    {
        if (state == IntPtr.Zero) return;
        try
        {
            WINTRUST_DATA closeData = new WINTRUST_DATA
            {
                cbStruct = (uint)Marshal.SizeOf<WINTRUST_DATA>(),
                dwStateAction = WTD_STATEACTION_CLOSE,
                hWVTStateData = state
            };
            Guid action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
            WinVerifyTrust(IntPtr.Zero, ref action, ref closeData);
        }
        catch { }
    }

    private static bool IsMicrosoftSession(IntPtr state)
    {
        if (state == IntPtr.Zero) return false;
        try
        {
            IntPtr pProvData = WTHelperProvDataFromStateData(state);
            return pProvData != IntPtr.Zero && IsMicrosoftChain(pProvData);
        }
        catch
        {
            return false;
        }
    }

    /// <summary>
    /// True only when the signer's whole certificate chain — leaf, intermediates and root —
    /// names Microsoft. The previous test inspected one subject string and accepted any
    /// certificate carrying "Microsoft Corporation" in it, so a squatted name passed. The chain
    /// array is walked at its native stride (each entry's cbStruct) instead of assuming our
    /// struct size matches.
    /// </summary>
    private static bool IsMicrosoftChain(IntPtr pProvData)
    {
        IntPtr pSigner = WTHelperGetProvSignerFromChain(pProvData, 0, BOOL.FALSE, 0);
        if (pSigner == IntPtr.Zero) return false;

        CRYPT_PROVIDER_SGNR sgnr = Marshal.PtrToStructure<CRYPT_PROVIDER_SGNR>(pSigner);
        if (sgnr.pasCertChain == IntPtr.Zero || sgnr.csCertChain == 0) return false;

        int stride = Marshal.ReadInt32(sgnr.pasCertChain); // cbStruct of entry 0
        int nativeSize = Marshal.SizeOf<CRYPT_PROVIDER_CERT>();
        if (stride < nativeSize || stride > 512) return false;

        uint count = Math.Min(sgnr.csCertChain, 8u);
        for (uint i = 0; i < count; i++)
        {
            CRYPT_PROVIDER_CERT cert = Marshal.PtrToStructure<CRYPT_PROVIDER_CERT>(sgnr.pasCertChain + (int)(i * stride));
            if (cert.pCert == IntPtr.Zero) return false;
            string? subject = GetCertSubjectName(cert.pCert);
            if (string.IsNullOrEmpty(subject) || !subject.Contains("Microsoft", StringComparison.OrdinalIgnoreCase))
                return false;
        }
        return true;
    }

    private static string? GetCertSubjectName(IntPtr pCertContext)
    {
        try
        {
            uint size = CertGetNameStringW(pCertContext, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, IntPtr.Zero, null, 0);
            if (size <= 1) return null;

            char[] buffer = new char[size];
            fixed (char* pBuf = buffer)
            {
                uint got = CertGetNameStringW(pCertContext, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, IntPtr.Zero, pBuf, size);
                if (got > 1)
                {
                    return new string(pBuf);
                }
            }
        }
        catch { }
        return null;
    }

    private static string ReadFixedString(char* buffer, int capacity)
    {
        int length = 0;
        while (length < capacity && buffer[length] != '\0') length++;
        return new string(buffer, 0, length);
    }

    /// <summary>
    /// Headless check of both signature paths: notepad.exe is catalog-signed by a Microsoft
    /// chain, our own unsigned DLL must stay unsigned. No network, no kills.
    /// </summary>
    public static int SelfTest()
    {
        string notepad = Path.Combine(Environment.SystemDirectory, "notepad.exe");
        (SignatureState npState, bool npMs) = VerifyFile(notepad);
        string ownDll = Path.Combine(AppContext.BaseDirectory, "NexusAV.Engine.dll");
        (SignatureState ownState, bool ownMs) = VerifyFile(ownDll);

        bool npOk = npState == SignatureState.MicrosoftSigned && npMs;
        bool ownOk = ownState == SignatureState.Unsigned && !ownMs;
        Console.WriteLine($"[SIG-SELFTEST] notepad.exe -> {npState} isMicrosoft={npMs} ({(npOk ? "ok" : "FAIL")})");
        Console.WriteLine($"[SIG-SELFTEST] NexusAV.Engine.dll -> {ownState} isMicrosoft={ownMs} ({(ownOk ? "ok" : "FAIL")})");
        Console.WriteLine(npOk && ownOk ? "[SIG-SELFTEST] PASS" : "[SIG-SELFTEST] FAIL");
        return npOk && ownOk ? 0 : 1;
    }

    public static SignatureStatus VerifyFileSignature(string filePath)
    {
        try
        {
            var (state, _) = VerifyFile(filePath);
            return state switch
            {
                SignatureState.MicrosoftSigned or SignatureState.TrustedPublisher => SignatureStatus.Valid,
                SignatureState.Unsigned => SignatureStatus.Unsigned,
                SignatureState.Untrusted => SignatureStatus.Untrusted,
                SignatureState.Invalid => SignatureStatus.Invalid,
                _ => SignatureStatus.Unknown,
            };
        }
        catch { return SignatureStatus.Unknown; }
    }
}

public enum BOOL : int
{
    FALSE = 0,
    TRUE = 1
}
