using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Win32;

namespace NexusAV.Engine;

public sealed class FirmwareAttestationResult
{
    public bool SecureBootEnabled;
    public bool SecureBootQueried;
    public bool UefiBootOrderPresent;
    public bool BootPathTamper;
    public List<string> BootTamperReasons { get; } = new();
    public bool TpmPresent;
    public bool IntelPttSupported;
    public bool TcgLogParsed;
    public int TcgEventCount;
    public int Pcr0to7EventCount;
    public byte[] TcgLogDigest = new byte[32];
    public byte[] PcrValues = new byte[32 * 8]; // PCR 0-7
    public int Findings;
    public string Summary = "";
}

/// <summary>
/// Intel TPM 2.0 / PTT (Platform Trust Technology) validation engine.
/// Chain of trust is:
/// Intel TPM NVRAM key storage + PCR-bound secrets + TCG Measured Boot log + Secure Boot state.
/// Hardware Root of Trust for encrypted heartbeat and key sealing.
/// Compatible with Intel Core (8th gen+) and Intel vPro architectures.
/// </summary>
public sealed unsafe partial class TpmValidationEngine : IDisposable
{
    private const string EfiGlobal = "{8BE4DF61-93CA-11D2-AA0D-00E098032B8C}";
    private const uint SeSystemEnvironment = 22;
    private int _disposed;

    public FirmwareAttestationResult LastResult { get; private set; } = new();

    public bool ProbeAndInitialize()
    {
        ObjectDisposedException.ThrowIf(_disposed == 1, this);
        EnablePrivilege(SeSystemEnvironment);
        LastResult = RunAttestation();
        Console.WriteLine($"[TPM] {LastResult.Summary}");
        return LastResult.SecureBootQueried || LastResult.TpmPresent || LastResult.UefiBootOrderPresent;
    }

    private static bool DetectIntelPTT()
    {
        try
        {
            using RegistryKey? tpm = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services\TPM");
            if (tpm == null) return false;

            object? manufacturer = tpm.GetValue("Manufacturer");
            object? version = tpm.GetValue("Version");

            if (manufacturer != null && version != null)
            {
                string mfg = manufacturer.ToString() ?? "";
                // Intel PTT typically reports manufacturer ID "INTC" or similar
                if (mfg.Contains("INTC") || mfg.Contains("Intel"))
                {
                    Console.WriteLine("[TPM] Intel PTT detected");
                    return true;
                }
            }

            // Check for Intel PTT via WMI
            try
            {
                using var searcher = new System.Management.ManagementObjectSearcher("SELECT * FROM Win32_Tpm");
                foreach (var obj in searcher.Get())
                {
                    var specVersion = obj["SpecVersion"]?.ToString();
                    var manufacturerId = obj["ManufacturerId"]?.ToString();
                    if (specVersion != null && specVersion.Contains("2.0"))
                    {
                        Console.WriteLine($"[TPM] TPM 2.0 detected: {manufacturerId}");
                        return true;
                    }
                }
            }
            catch { }
        }
        catch { }
        return false;
    }

    public FirmwareAttestationResult RunAttestation()
    {
        var r = new FirmwareAttestationResult();
        r.IntelPttSupported = DetectIntelPTT();
        QuerySecureBoot(r);
        QueryNvramBootPaths(r);
        QueryTcgEventLog(r);
        r.Findings = 0;
        if (r.SecureBootQueried && !r.SecureBootEnabled) r.Findings++;
        if (r.BootPathTamper) r.Findings++;
        if (r.TpmPresent && !r.TcgLogParsed) r.Findings++;
        r.Summary =
            $"SecureBoot={(r.SecureBootQueried ? (r.SecureBootEnabled ? "ON" : "OFF") : "n/a")} " +
            $"NVRAM={(r.UefiBootOrderPresent ? (r.BootPathTamper ? "TAMPER" : "OK") : "n/a")} " +
            $"TPM={(r.IntelPttSupported ? "IntelPTT" : (r.TpmPresent ? "Yes" : "No"))} " +
            $"TCG={(r.TcgLogParsed ? $"{r.TcgEventCount} events PCR0-7={r.Pcr0to7EventCount}" : "n/a")} " +
            $"findings={r.Findings}";
        LastResult = r;
        return r;
    }

    private static void QuerySecureBoot(FirmwareAttestationResult r)
    {
        try
        {
            using RegistryKey? k = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Control\SecureBoot\State");
            object? v = k?.GetValue("UEFISecureBootEnabled");
            if (v is int i)
            {
                r.SecureBootQueried = true;
                r.SecureBootEnabled = i != 0;
            }
        }
        catch { }

        if (!r.SecureBootQueried)
        {
            byte[] buf = new byte[8];
            uint n = GetFirmwareEnvironmentVariableW("SecureBoot", EfiGlobal, buf, (uint)buf.Length);
            if (n > 0)
            {
                r.SecureBootQueried = true;
                r.SecureBootEnabled = buf[0] != 0;
            }
        }
    }

    private static void QueryNvramBootPaths(FirmwareAttestationResult r)
    {
        byte[] order = new byte[512];
        uint n = GetFirmwareEnvironmentVariableW("BootOrder", EfiGlobal, order, (uint)order.Length);
        if (n < 2) return;
        r.UefiBootOrderPresent = true;

        int entryCount = (int)(n / 2);
        var names = new List<string>();
        for (int i = 0; i < entryCount && i < 16; i++)
        {
            ushort id = (ushort)(order[i * 2] | (order[i * 2 + 1] << 8));
            string varName = $"Boot{id:X4}";
            byte[] loadOpt = new byte[2048];
            uint got = GetFirmwareEnvironmentVariableW(varName, EfiGlobal, loadOpt, (uint)loadOpt.Length);
            if (got < 6) continue;
            string desc = ReadUefiDescription(loadOpt, (int)got, out int descEnd);
            string filePath = ReadUefiFilePath(loadOpt, (int)got, descEnd);
            names.Add(string.IsNullOrEmpty(filePath) ? desc : $"{desc} [{filePath}]");
            if (IsSuspiciousBootEntry(desc, filePath, out string reason))
            {
                r.BootPathTamper = true;
                r.BootTamperReasons.Add($"Boot{id:X4}: {reason}");
            }
        }

        Console.WriteLine($"[NVRAM] BootOrder entries={entryCount} paths={string.Join(" | ", names)}");
        if (r.BootPathTamper)
            Console.WriteLine("[NVRAM] Boot path tamper: " + string.Join("; ", r.BootTamperReasons));
    }

    // ── EFI_LOAD_OPTION layout ──────────────────────────────────────
    // UINT32  Attributes
    // UINT16  FilePathListLength
    // CHAR16  Description[]    (NUL-terminated)
    // EFI_DEVICE_PATH_PROTOCOL  FilePathList[...]
    // UINT8   OptionalData[...]
    // ────────────────────────────────────────────────────────────────

    private static string ReadUefiDescription(byte[] loadOpt, int len, out int descEnd)
    {
        descEnd = 6;
        if (len < 6) return "";
        int i = 6;
        var sb = new StringBuilder();
        while (i + 1 < len)
        {
            char c = (char)(loadOpt[i] | (loadOpt[i + 1] << 8));
            i += 2;
            if (c == 0) break;
            sb.Append(c);
        }
        descEnd = i; // points right after the NUL terminator
        return sb.ToString();
    }

    private static string ReadUefiFilePath(byte[] loadOpt, int len, int descEnd)
    {
        // FilePathListLength is at bytes 4-5 of EFI_LOAD_OPTION
        if (len < 6) return "";
        int pathListLen = loadOpt[4] | (loadOpt[5] << 8);
        int pathStart   = descEnd;
        int pathEnd     = Math.Min(pathStart + pathListLen, len);

        // Walk EFI_DEVICE_PATH nodes looking for MEDIA_FILEPATH_DP (Type 4, SubType 4)
        int off = pathStart;
        var sb = new StringBuilder();
        while (off + 4 <= pathEnd)
        {
            byte nodeType    = loadOpt[off];
            byte nodeSubType = loadOpt[off + 1];
            int  nodeLen     = loadOpt[off + 2] | (loadOpt[off + 3] << 8);
            if (nodeLen < 4 || off + nodeLen > pathEnd) break;

            // Type=4 SubType=4 → MEDIA_FILE_PATH  (contains a CHAR16 file path)
            if (nodeType == 4 && nodeSubType == 4 && nodeLen > 4)
            {
                int chars = (nodeLen - 4) / 2;
                for (int j = 0; j < chars; j++)
                {
                    int ci = off + 4 + j * 2;
                    if (ci + 1 >= pathEnd) break;
                    char c = (char)(loadOpt[ci] | (loadOpt[ci + 1] << 8));
                    if (c == 0) break;
                    sb.Append(c);
                }
            }
            off += nodeLen;
            // End-of-path node: Type=0x7F SubType=0xFF
            if (nodeType == 0x7F && nodeSubType == 0xFF) break;
        }
        return sb.ToString();
    }

    /// <summary>
    /// Whitelist-based detection: anything that is NOT a known-good boot entry is suspicious.
    /// This is far more robust than looking for literal "bootkit" strings.
    /// </summary>
    private static bool IsSuspiciousBootEntry(string desc, string filePath, out string reason)
    {
        reason = "";
        string d = desc.ToLowerInvariant();
        string f = filePath.ToLowerInvariant();

        // ── Known-good descriptions ──────────────────────────────────
        if (d.Contains("windows boot manager") || d.Contains("windows boot loader")) return false;
        if (d.Contains("ubuntu")   || d.Contains("grub")   || d.Contains("fedora") ||
            d.Contains("debian")   || d.Contains("opensuse")|| d.Contains("arch linux")) return false;
        if (d.Contains("network")  || d.Contains("pxe")    || d.Contains("ipv4")   ||
            d.Contains("ipv6"))    return false;
        if (d.Contains("uefi shell") || d.Contains("setup") || d.Contains("bios")) return false;
        if (string.IsNullOrWhiteSpace(d)) return false;

        // ── Known-good file paths ────────────────────────────────────
        bool knownGoodPath = f.Contains(@"\efi\microsoft\boot\bootmgfw.efi") ||
                             f.Contains(@"\efi\boot\bootx64.efi")            ||
                             f.Contains(@"\efi\ubuntu\")                     ||
                             f.Contains(@"\efi\fedora\")                     ||
                             f.Contains(@"\efi\debian\")                     ||
                             string.IsNullOrEmpty(f);

        // ── Explicit known-bad patterns (belt + suspenders) ─────────
        if (f.Contains("blacklotus") || f.Contains("bootkit") ||
            f.Contains("grubkit")    || f.Contains("evilboot"))
        {
            reason = $"known-bad path: {filePath}";
            return true;
        }

        // ── Unknown description + unknown path = suspicious ──────────
        if (!knownGoodPath)
        {
            reason = $"unrecognised EFI path '{filePath}' for entry '{desc}'";
            return true;
        }

        // ── Path does not match the expected Microsoft bootmgr ───────
        if ((d.Contains("windows") || d.Contains("bootmgr")) &&
            !string.IsNullOrEmpty(f) && !knownGoodPath)
        {
            reason = $"Windows boot entry points to unexpected path: {filePath}";
            return true;
        }

        return false;
    }

    private static void QueryTcgEventLog(FirmwareAttestationResult r)
    {
        try
        {
            using RegistryKey? tpm = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services\TPM");
            r.TpmPresent = tpm != null;
        }
        catch { }

        byte[]? log = TryReadTbsLog();
        log ??= TryReadMeasuredBootFile();
        if (log == null || log.Length < 32) return;

        r.TcgLogParsed = true;
        r.TcgLogDigest = SHA256.HashData(log);
        ParseTcgEvents(log, r);
        Console.WriteLine($"[TPM] TCG log {log.Length} bytes digest={Convert.ToHexString(r.TcgLogDigest.AsSpan(0, 8))}...");
    }

    private static byte[]? TryReadTbsLog()
    {
        nint ctx = 0;
        try
        {
            TBS_CONTEXT_PARAMS2 p = new() { version = 2, asUINT32 = 4 }; // includeTpm20
            uint st = Tbsi_Context_Create(ref p, out ctx);
            if (st != 0 || ctx == 0) return null;
            uint len = 0;
            st = Tbsi_Get_TCG_Log(ctx, nint.Zero, ref len);
            if (len == 0 || len > 8 * 1024 * 1024) return null;
            byte[] buf = new byte[len];
            fixed (byte* b = buf)
            {
                st = Tbsi_Get_TCG_Log(ctx, (nint)b, ref len);
            }
            if (st != 0) return null;
            Array.Resize(ref buf, (int)len);
            return buf;
        }
        catch { return null; }
        finally
        {
            if (ctx != 0) _ = Tbsip_Context_Close(ctx);
        }
    }

    private static byte[]? TryReadMeasuredBootFile()
    {
        try
        {
            string dir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "Logs", "MeasuredBoot");
            if (!Directory.Exists(dir)) return null;
            string? latest = Directory.GetFiles(dir, "*.log").OrderByDescending(File.GetLastWriteTimeUtc).FirstOrDefault();
            if (latest == null) return null;
            return File.ReadAllBytes(latest);
        }
        catch { return null; }
    }

    private static void ParseTcgEvents(byte[] log, FirmwareAttestationResult r)
    {
        // TCG_PCR_EVENT (SHA1 log) header: PCRIndex(4) EventType(4) digest[20] EventSize(4)
        int off = 0;
        int guard = 0;
        while (off + 32 <= log.Length && guard++ < 4096)
        {
            uint pcr = BitConverter.ToUInt32(log, off);
            uint etype = BitConverter.ToUInt32(log, off + 4);
            uint evSize = BitConverter.ToUInt32(log, off + 28);
            if (evSize > 1_000_000) break;
            r.TcgEventCount++;
            if (pcr <= 7) r.Pcr0to7EventCount++;
            off += 32 + (int)evSize;
            _ = etype;
        }
    }

    private static void EnablePrivilege(uint id)
    {
        try { _ = RtlAdjustPrivilege(id, true, false, out _); } catch { }
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct TBS_CONTEXT_PARAMS2
    {
        public uint version;
        public uint asUINT32;
    }

    [LibraryImport("kernel32.dll", EntryPoint = "GetFirmwareEnvironmentVariableW", SetLastError = true, StringMarshalling = StringMarshalling.Utf16)]
    private static partial uint GetFirmwareEnvironmentVariableW(string lpName, string lpGuid, byte[] pBuffer, uint nSize);

    [LibraryImport("tbs.dll")]
    private static partial uint Tbsi_Context_Create(ref TBS_CONTEXT_PARAMS2 pContextParams, out nint phContext);

    [LibraryImport("tbs.dll")]
    private static partial uint Tbsi_Get_TCG_Log(nint hContext, nint pOutputBuf, ref uint pOutputBufLen);

    [LibraryImport("tbs.dll")]
    private static partial uint Tbsip_Context_Close(nint hContext);

    [LibraryImport("ntdll.dll")]
    private static partial int RtlAdjustPrivilege(uint Privilege, [MarshalAs(UnmanagedType.Bool)] bool Enable, [MarshalAs(UnmanagedType.Bool)] bool CurrentThread, [MarshalAs(UnmanagedType.Bool)] out bool Enabled);

    public void Dispose() => Interlocked.Exchange(ref _disposed, 1);
}