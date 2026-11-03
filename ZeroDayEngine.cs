using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;

namespace NexusAV.Engine;

/// <summary>Result of one local, signature-free analysis of a single file.</summary>
public sealed class ZeroDayVerdict
{
    public string FilePath = string.Empty;
    public bool IsPortableExecutable;
    public bool ManagedDotNet;
    public int Score;
    public long SizeBytes;
    public readonly List<string> Signals = new();

    public bool IsBlocker => Score >= ZeroDayEngine.BlockScoreThreshold;
    public bool IsWatchable => Score >= ZeroDayEngine.WatchScoreThreshold;

    public string SignalText => Signals.Count == 0 ? "no suspicious structure found" : string.Join("; ", Signals);

    public string Summary =>
        $"{(IsPortableExecutable ? "PE" : "non-PE")}{(ManagedDotNet ? "/.NET" : "")} score={Score} size={SizeBytes} :: {SignalText}";
}

/// <summary>
/// THE THIRD ENGINE — signature-free detection of unknown / zero-day files.
///
/// VirusTotal answers "have we seen this hash before". It can never answer "is this
/// never-before-seen file hostile", which is exactly the zero-day case the product exists for.
/// This engine reads the file's own bytes and judges how it was BUILT: section entropy,
/// entry-point placement, import-table shape, writable+executable memory layout, resource
/// packing, signature state and where the file sits on disk.
///
/// Deliberately: no cloud call, no local signature database, no WDAC/AppLocker policy, no
/// registry policy key, no DLL injection into other processes. Everything it does is a file
/// read plus, for a blocker, one reversible NtSuspendProcess on the process that ran it
/// (thawable from the GUI). Machine state is never changed.
/// </summary>
public sealed class ZeroDayEngine : IDisposable
{
    /// <summary>Score at or above which the analyzer considers the file hostile enough to halt it.</summary>
    public const int BlockScoreThreshold = 75;

    /// <summary>Score at or above which the file is reported to the analyst without any action.</summary>
    public const int WatchScoreThreshold = 55;

    private const int MaxFileBytes = 12 * 1024 * 1024;
    private const int MaxEntropySample = 512 * 1024;

    // Whitelist, not a blocklist. Reading bytes and parsing headers is cheap but not free, and a
    // machine-wide file watcher touches thousands of files a minute; analysing only code files and
    // the document types attackers use as lures keeps this engine invisible to a working PC.
    private static readonly HashSet<string> CodeExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".exe", ".dll", ".scr", ".sys", ".ocx", ".cpl", ".drv", ".com", ".pif", ".msi", ".appx"
    };

    private static readonly HashSet<string> LureExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".jpg", ".jpeg", ".png",
        ".txt", ".zip", ".iso", ".bat", ".cmd", ".vbs", ".js", ".lnk", ".url", ".hta", ".jar"
    };

    // Images whose real system copy lives in System32; a copy of this name anywhere else is a
    // masquerade, which is worth more than any structural signal.
    /// <summary>True when a file type is worth opening at all: code files and document lures.</summary>
    public static bool IsWorthAnalyzing(string? extension) =>
        !string.IsNullOrEmpty(extension) && (CodeExtensions.Contains(extension) || LureExtensions.Contains(extension));

    private static readonly HashSet<string> SystemImageNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "svchost.exe", "lsass.exe", "csrss.exe", "services.exe", "wininit.exe", "winlogon.exe",
        "smss.exe", "explorer.exe", "taskhostw.exe", "runtimebroker.exe", "dllhost.exe",
        "conhost.exe", "searchindexer.exe", "audiodg.exe", "spoolsv.exe", "dwm.exe", "sihost.exe"
    };

    private static readonly HashSet<string> InjectionApis = new(StringComparer.OrdinalIgnoreCase)
    {
        "VirtualAllocEx", "VirtualAllocExNuma", "WriteProcessMemory", "CreateRemoteThread",
        "CreateRemoteThreadEx", "RtlCreateUserThread", "NtUnmapViewOfSection", "NtAllocateVirtualMemory",
        "NtWriteVirtualMemory", "SetThreadContext", "GetThreadContext", "QueueUserAPC",
        "NtMapViewOfSection", "NtCreateThreadEx", "ReadProcessMemory", "OpenProcess"
    };

    private static readonly HashSet<string> AntiDebugApis = new(StringComparer.OrdinalIgnoreCase)
    {
        "IsDebuggerPresent", "CheckRemoteDebuggerPresent", "NtQueryInformationProcess",
        "OutputDebugStringA", "OutputDebugStringW", "NtSetInformationThread", "NtQuerySystemInformation"
    };

    private static readonly HashSet<string> DownloadApis = new(StringComparer.OrdinalIgnoreCase)
    {
        "URLDownloadToFileA", "URLDownloadToFileW", "WinHttpOpen", "WinHttpConnect", "WinHttpReadData",
        "InternetOpenUrlA", "InternetOpenUrlW", "InternetReadFile", "socket", "connect", "send",
        "WSAStartup", "getaddrinfo"
    };

    private static readonly HashSet<string> PersistApis = new(StringComparer.OrdinalIgnoreCase)
    {
        "RegSetValueExA", "RegSetValueExW", "RegCreateKeyExA", "RegCreateKeyExW",
        "CreateServiceA", "CreateServiceW", "OpenSCManagerA", "OpenSCManagerW",
        "SetWindowsHookExA", "SetWindowsHookExW", "CreateNamedPipeA", "MoveFileExA", "MoveFileExW"
    };

    private static readonly HashSet<string> CredentialApis = new(StringComparer.OrdinalIgnoreCase)
    {
        "LsaOpenProcess", "LsaEnumerateLogonSessions", "OpenProcessToken", "DuplicateTokenEx",
        "AcquireCredentialsHandleA", "CredReadA", "CredReadW", "CryptUnprotectData", "NetUserEnum"
    };

    private readonly ConcurrentDictionary<string, (long Length, DateTime Written, ZeroDayVerdict Verdict)> _cache =
        new(StringComparer.OrdinalIgnoreCase);

    private readonly Thread? _watchThread;
    private readonly Thread? _workThread;
    private readonly CancellationTokenSource _cts = new();
    private readonly HashSet<uint> _seenPids = new();
    private readonly object _seenLock = new();
    private readonly BlockingCollection<(uint Pid, string Path)> _queue = new(256);
    private bool _baselineDone;

    private int _analyses;
    private int _flagged;
    private int _halted;
    private int _cacheHits;
    private int _dropped;

    /// <summary>Raised for every file that reaches the watch threshold, on the analyzer thread.</summary>
    public event Action<ZeroDayVerdict, string>? OnVerdict;

    /// <summary>User-configured path exceptions; the automatic pipeline skips them. Explicit
    /// analyst inspection (the zday command) still works — the whitelist is never a lockout.</summary>
    public WhitelistManager? Whitelist { get; set; }

    /// <summary>Known-bad fingerprint store. An exact identity match outranks every heuristic here.</summary>
    public FingerprintStore? Fingerprints { get; set; }

    public ZeroDayEngine()
    {
        _watchThread = new Thread(ExecWatchLoop) { IsBackground = true, Name = "nexus-zeroday-watch" };
        // One worker, not one per process: reading a 12 MB image and verifying its authenticode
        // signature is slow, and the machine must never feel this engine working.
        _workThread = new Thread(WorkLoop) { IsBackground = true, Name = "nexus-zeroday-work" };
    }

    public void Start()
    {
        Volatile.Write(ref _isRunning, 1);
        _workThread?.Start();
        _watchThread?.Start();
        Console.WriteLine("[ZERODAY] Signature-free file engine active (structure + imports + entropy; local only, no policy, no injection)");
        EventBus.Status($"zeroday_state active=1 threshold={BlockScoreThreshold}");
    }

    private int _isRunning;

    public (int Analyses, int Flagged, int Halted, int CacheHits, int Dropped) GetStats()
        => (Volatile.Read(ref _analyses), Volatile.Read(ref _flagged), Volatile.Read(ref _halted),
            Volatile.Read(ref _cacheHits), Volatile.Read(ref _dropped));

    public void Dispose()
    {
        Volatile.Write(ref _isRunning, 0);
        _cts.Cancel();
        _queue.CompleteAdding();
    }

    // ---------------------------------------------------------------- on-demand entry points

    /// <summary>
    /// Analyze one path. Returns null when the file is skipped by design (excluded extension,
    /// missing, too small to be interesting) — callers must treat null as "not analysed",
    /// never as "clean".
    /// </summary>
    public ZeroDayVerdict? Analyze(string path, bool useCache = true)
    {
        try
        {
            if (string.IsNullOrEmpty(path)) return null;
            var fi = new FileInfo(path);
            if (!fi.Exists) return null;
            if (fi.Length < 64) return null;
            if (fi.Length > 80L * 1024 * 1024) return null; // installers/archives: sampling would mislead
            string ext = fi.Extension;
            if (!CodeExtensions.Contains(ext) && !LureExtensions.Contains(ext)) return null;

            long len = fi.Length;
            DateTime written = fi.LastWriteTimeUtc;
            if (useCache && _cache.TryGetValue(path, out var hit)
                && hit.Length == len && hit.Written == written)
            {
                Interlocked.Increment(ref _cacheHits);
                return hit.Verdict;
            }

            Interlocked.Increment(ref _analyses);
            byte[] head = ReadHead(path, out long available);
            if (head.Length == 0) return null;

            var v = new ZeroDayVerdict { FilePath = path, SizeBytes = len };
            bool isPe = IsPe(head);
            v.IsPortableExecutable = isPe;

            if (isPe)
                AnalyzePe(head, available, path, v);
            else
                AnalyzeNonPe(head, path, v);

            if (v.Score > 100) v.Score = 100;
            if (v.Score < 0) v.Score = 0;

            if (_cache.Count > 4000) _cache.Clear();
            if (useCache) _cache[path] = (len, written, v);

            if (v.IsWatchable) Interlocked.Increment(ref _flagged);
            OnVerdict?.Invoke(v, useCache ? "cache" : "fresh");
            return v;
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[ZERODAY] analyze failed for {path}: {ex.Message}");
            return null;
        }
    }

    private static byte[] ReadHead(string path, out long available)
    {
        available = 0;
        try
        {
            using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            int cap = (int)Math.Min(fs.Length, MaxFileBytes);
            var buf = new byte[cap];
            int got = 0;
            while (got < cap)
            {
                int r = fs.Read(buf, got, cap - got);
                if (r <= 0) break;
                got += r;
            }
            available = fs.Length;
            if (got < cap) Array.Resize(ref buf, got);
            return buf;
        }
        catch
        {
            // Locked by its writer (browser installers, unpackers) — this is churn, not a verdict.
            return Array.Empty<byte>();
        }
    }

    private static bool IsPe(byte[] b) =>
        b.Length > 0x40 && b[0] == 0x4D && b[1] == 0x5A;

    // ---------------------------------------------------------------- PE structure analysis

    private void AnalyzePe(byte[] b, long fileLength, string path, ZeroDayVerdict v)
    {
        void Add(int points, string signal)
        {
            v.Score += points;
            v.Signals.Add(signal);
        }

        // A file that calls itself a document but starts with MZ is the phishing lure, whatever
        // its internals look like. Checked first because it applies to corrupt headers too.
        string lowerName = Path.GetFileName(path).ToLowerInvariant();
        foreach (var docExt in new[] { ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".jpg", ".jpeg", ".png", ".txt", ".iso", ".zip" })
        {
            if (lowerName.EndsWith(docExt) && !Path.GetFileNameWithoutExtension(lowerName).EndsWith(".exe", StringComparison.Ordinal))
            {
                Add(30, $"named '{docExt}' but its first bytes are an executable (PE) header");
                break;
            }
        }

        int e_lfanew = ReadI32(b, 0x3C);
        if (e_lfanew <= 0 || e_lfanew + 24 >= b.Length || ReadU16(b, e_lfanew) != 0x4550)
        {
            Add(30, "declares itself a PE (MZ) but the PE header is corrupt or forged");
            return;
        }

        ushort machine = ReadU16(b, e_lfanew + 4);
        ushort nSections = ReadU16(b, e_lfanew + 6);
        ushort sizeOfOpt = ReadU16(b, e_lfanew + 20);
        ushort characteristics = ReadU16(b, e_lfanew + 22);
        bool isDll = (characteristics & 0x2000) != 0;
        int optStart = e_lfanew + 24;
        if (optStart + 2 >= b.Length || nSections == 0 || nSections > 96)
        {
            Add(20, $"implausible section count {nSections}");
            return;
        }

        ushort magic = ReadU16(b, optStart);
        bool pe32Plus = magic == 0x20B;
        if (magic != 0x10B && !pe32Plus)
        {
            Add(20, $"unknown optional-header magic 0x{magic:X4}");
            return;
        }

        uint entryRva = ReadU32(b, optStart + 16);
        int secStart = optStart + sizeOfOpt;
        if (secStart + 40 > b.Length) { Add(15, "section table runs past the file"); return; }

        uint timestamp = ReadU32(b, e_lfanew + 8);

        // .NET check: CLI header is data directory 14.
        int ddStart = optStart + (pe32Plus ? 112 : 96);
        uint cor20Rva = 0, importRva = 0, importSize = 0, resourceRva = 0, resourceSize = 0;
        if (ddStart + 15 * 8 + 8 <= b.Length)
        {
            importRva = ReadU32(b, ddStart + 1 * 8);
            importSize = ReadU32(b, ddStart + 1 * 8 + 4);
            resourceRva = ReadU32(b, ddStart + 2 * 8);
            resourceSize = ReadU32(b, ddStart + 2 * 8 + 4);
            cor20Rva = ReadU32(b, ddStart + 14 * 8);
        }
        v.ManagedDotNet = cor20Rva != 0;

        // ---- section table
        var names = new string[nSections];
        var va = new uint[nSections];
        var vsz = new uint[nSections];
        var raw = new uint[nSections];
        var rawPtr = new uint[nSections];
        var chars = new uint[nSections];
        var ent = new double[nSections];

        double maxEnt = 0; int maxEntIdx = -1;
        for (int i = 0; i < nSections; i++)
        {
            int o = secStart + i * 40;
            if (o + 40 > b.Length) break;
            names[i] = ReadName(b, o, 8);
            va[i] = ReadU32(b, o + 12);
            vsz[i] = ReadU32(b, o + 8);
            raw[i] = ReadU32(b, o + 16);
            rawPtr[i] = ReadU32(b, o + 20);
            chars[i] = ReadU32(b, o + 36);
            ent[i] = SectionEntropy(b, rawPtr[i], raw[i]);
            if (ent[i] > maxEnt) { maxEnt = ent[i]; maxEntIdx = i; }
        }

        // 1) Packer / encrypted payload: an executable section full of incompressible bytes.
        if (maxEntIdx >= 0 && (chars[maxEntIdx] & 0x20000000) != 0) // IMAGE_SCN_MEM_EXECUTE
        {
            double cut = v.ManagedDotNet ? 7.45 : 7.20;
            if (maxEnt >= cut)
                Add(v.ManagedDotNet ? 18 : 28, $"section '{names[maxEntIdx]}' is executable with entropy {maxEnt:F2}/8 (packed or encrypted code)");
            else if (maxEnt >= 6.9 && !v.ManagedDotNet)
                Add(14, $"section '{names[maxEntIdx]}' entropy {maxEnt:F2}/8 is high for plain compiled code");
        }

        // 2) Entry point placement — a packed stub jumps into the high-entropy area, not .text.
        int epIdx = SectionOf(va, vsz, entryRva);
        if (epIdx < 0)
            Add(18, $"entry point RVA 0x{entryRva:X} maps to no section (manually built header)");
        else
        {
            if ((chars[epIdx] & 0x00000020) == 0) // CONTENTS_CODE
                Add(12, $"entry point is in '{names[epIdx]}', which holds no code flag");
            if (ent[epIdx] >= (v.ManagedDotNet ? 7.4 : 7.0))
                Add(22, $"entry point executes from high-entropy section '{names[epIdx]}' ({ent[epIdx]:F2})");
            if (!v.ManagedDotNet && epIdx == nSections - 1 && nSections >= 3 && maxEntIdx == epIdx)
                Add(10, $"entry point sits in the LAST section '{names[epIdx]}' (classic unpacker stub placement)");
        }

        // 3) Writable AND executable memory in one region: self-modifying / shellcode landing pad.
        for (int i = 0; i < nSections; i++)
        {
            bool wx = (chars[i] & 0x80000000) != 0 && (chars[i] & 0x40000000) != 0 && (chars[i] & 0x20000000) != 0;
            bool uninitializedExec = (chars[i] & 0x20000000) != 0 && raw[i] == 0 && vsz[i] > 0x1000;
            if (wx && !v.ManagedDotNet)
            {
                Add(18, $"section '{names[i]}' is readable, writable AND executable");
                break;
            }
            if (uninitializedExec)
            {
                Add(10, $"executable section '{names[i]}' has no bytes on disk but reserves 0x{vsz[i]:X} in memory");
                break;
            }
        }

        // 4) Import table.
        var dlls = new List<string>();
        var funcs = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        int inj = 0, dbg = 0, dl = 0, per = 0, cred = 0;
        bool importParseOk = ReadImports(b, ddStart, va, vsz, raw, rawPtr, nSections, pe32Plus, dlls, funcs);

        if (!v.ManagedDotNet && (importRva == 0 || importSize == 0))
            Add(26, "executable image with an empty import table (manual API resolver / loader stub)");

        if (importParseOk)
        {
            inj = InjectionApis.Count(funcs.Contains);
            dbg = AntiDebugApis.Count(funcs.Contains);
            dl = DownloadApis.Count(funcs.Contains);
            per = PersistApis.Count(funcs.Contains);
            cred = CredentialApis.Count(funcs.Contains);

            int fromImports = 0;
            if (inj >= 3) fromImports += 26;
            else if (inj >= 2) fromImports += 16;
            if (inj >= 2) Add(fromImports, $"process-injection API set ({inj} of: {Preview(funcs, InjectionApis)})");

            if (dbg >= 2) Add(12, $"anti-debugging APIs ({dbg})");
            else if (dbg == 1 && inj >= 1) Add(8, "anti-debug API next to injection API");

            if (dl >= 2 && inj >= 1) Add(14, $"stage-2 download APIs alongside injection ({dl} network calls)");
            else if (dl >= 3) Add(12, $"network download API set ({dl})");

            if (cred >= 2) Add(18, $"credential-access APIs ({cred})");
            else if (cred == 1 && inj >= 2) Add(12, "credential API combined with an injection set");

            if (per >= 2) Add(12, $"persistence APIs ({per})");

            if (dlls.Any(d => d.Equals("ntdll.dll", StringComparison.OrdinalIgnoreCase)) &&
                inj >= 2 &&
                !dlls.Any(d => d.EndsWith("kernel32.dll", StringComparison.OrdinalIgnoreCase)))
                Add(14, "direct ntdll syscalls with no kernel32 import (syscall stub loader)");

            if (funcs.Count == 0 && importRva != 0)
                Add(15, "import directory declared but resolves to no names (deliberately broken table)");
        }

        // 5) Embedded PE inside the resource section — dropper lure pattern.
        if (resourceRva != 0 && resourceSize != 0)
        {
            int roff = RvaToOffset(va, raw, rawPtr, nSections, resourceRva);
            if (roff > 0 && roff < b.Length)
            {
                int limit = (int)Math.Min(resourceSize, b.Length - (long)roff);
                int found = CountPeMagic(b, roff, limit);
                if (found >= 1)
                    Add(24, $"{found} embedded PE image(s) hidden in the resource directory");
            }
        }

        // 6) Compile time anomalies.
        if (timestamp == 0) Add(6, "PE timestamp is zero (header scrubbed)");
        else
        {
            var built = DateTimeOffset.FromUnixTimeSeconds(timestamp);
            if (built > DateTimeOffset.UtcNow.AddDays(1)) Add(10, $"PE timestamp is in the future ({built:yyyy-MM-dd})");
            else if (built < new DateTimeOffset(2000, 1, 1, 0, 0, 0, TimeSpan.Zero)) Add(6, $"PE timestamp is implausibly old ({built:yyyy-MM-dd})");
        }

        // 7) A toolchain-built binary carries a linker version and relocations; a hand-made one
        //    often has none and pretends to be a GUI app.
        if (!isDll && fileLength < 64 * 1024 && (inj >= 2 || dl >= 2))
            Add(10, $"only {fileLength / 1024} KB but imports a full injection/download set (small loader stub)");

        // 8) Where the file lives and what it calls itself.
        string lower = path.ToLowerInvariant();
        string baseName = Path.GetFileName(lower);
        if (SystemImageNames.Contains(baseName) &&
            !lower.Contains("\\windows\\system32\\") && !lower.Contains("\\windows\\syswow64\\"))
            Add(35, $"'{baseName}' running outside System32/SysWOW64 (masquerade)");

        if (IsUserWritableDropLocation(lower))
            Add(10, "written to a user-writable drop location (temp/appdata/programdata/downloads)");

        string? lure = LureExtension(baseName);
        if (lure != null) Add(22, $"double extension '{lure}' — presents as a document, executes as a program");

        if (RandomLookingStem(Path.GetFileNameWithoutExtension(baseName)))
            Add(8, $"file name '{Path.GetFileNameWithoutExtension(baseName)}' looks machine-generated");

        if (!isDll && (characteristics & 0x0002) == 0)
            Add(8, "IMAGE_FILE_EXECUTABLE_IMAGE flag is not set yet the file is run as a program");

        // 9) Authenticode is the last step and only for files that already look wrong.
        //    WinVerifyTrust can reach out for certificate/revocation data, so calling it on every
        //    binary on the machine is exactly the kind of background load that stalls a working PC.
        if (v.Score >= 15)
        {
            var (state, msSigned) = WinTrust.VerifyFile(path);
            if (msSigned)
            {
                v.Score = 0;
                v.Signals.Clear();
                v.Signals.Add("authenticode signed by Microsoft");
                return;
            }
            switch (state)
            {
                case SignatureState.Invalid:
                case SignatureState.Untrusted:
                    Add(30, $"structurally unusual AND the authenticode signature is {state.ToString().ToLowerInvariant()}");
                    break;
                case SignatureState.TrustedPublisher:
                    v.Score = Math.Max(0, v.Score - 20);
                    v.Signals.Add("signed by a trusted publisher (-20)");
                    break;
                case SignatureState.Unsigned:
                    Add(12, "unsigned image");
                    break;
            }
        }
    }

    private static void AnalyzeNonPe(byte[] b, string path, ZeroDayVerdict v)
    {
        // A file whose name promises a document but whose bytes are code is the phishing lure.
        string baseName = Path.GetFileName(path).ToLowerInvariant();
        bool zip = b.Length > 4 && b[0] == 0x50 && b[1] == 0x4B && b[2] == 0x03 && b[3] == 0x04;
        if (zip)
        {
            if (LureExtension(baseName) != null)
            {
                v.Score += 18;
                v.Signals.Add("archive with a document-like double extension");
            }
            return;
        }
        // Office docs carrying VBA macros: the OLE compound header plus a macro stream name.
        bool ole = b.Length > 8 && b[0] == 0xD0 && b[1] == 0xCF && b[2] == 0x11 && b[3] == 0xE0;
        if (ole && (baseName.EndsWith(".doc") || baseName.EndsWith(".xls") || baseName.EndsWith(".ppt")))
        {
            int hits = CountAscii(b, "Macros/ThisDocument") + CountAscii(b, "_VBA_PROJECT") + CountAscii(b, "VBA");
            if (hits >= 1)
            {
                v.Score += 22;
                v.Signals.Add($"legacy Office document containing an embedded VBA macro project ({hits} marker(s))");
            }
        }
    }

    // ---------------------------------------------------------------- execution watcher

    /// <summary>
    /// Watches for processes that START while the engine runs. The very first sweep only records
    /// what is already running and analyses nothing: reading every image on the machine the second
    /// the console opens is precisely the disk storm that froze the PC before. Anything that starts
    /// afterwards is queued and drained one file at a time, slowly.
    /// </summary>
    private void ExecWatchLoop()
    {
        while (!_cts.IsCancellationRequested && Volatile.Read(ref _isRunning) != 0)
        {
            try
            {
                var fresh = new List<(uint Pid, string Path)>();
                int newlyTracked = 0;
                foreach (var entry in ProcessSnapshotCache.Snapshot)
                {
                    uint pid;
                    lock (_seenLock)
                    {
                        if (!_seenPids.Add(entry.Pid)) continue;
                        pid = entry.Pid;
                    }
                    newlyTracked++;
                    if (_baselineDone)
                    {
                        string path = SafeProcessKiller.ImagePathOf(pid);
                        if (path.Length != 0 && !SafeProcessKiller.IsProtectedImage(path))
                            fresh.Add((pid, path));
                    }
                }

                if (!_baselineDone)
                {
                    _baselineDone = true;
                    EventBus.Status($"zeroday_baseline recorded={newlyTracked} analysed=0 action=none (images already running when the engine started were not read)");
                    continue;
                }

                foreach (var item in fresh)
                {
                    if (!_queue.TryAdd(item))
                    {
                        Interlocked.Increment(ref _dropped);
                        EventBus.Status($"zeroday_dropped pid={item.Pid} queue=full");
                    }
                }

                // Forget pids that exited so the set cannot grow without bound.
                PruneDeadPids();
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[ZERODAY] exec watch error: {ex.Message}");
            }

            try { _cts.Token.WaitHandle.WaitOne(2000); }
            catch { break; }
        }
    }

    private void PruneDeadPids()
    {
        var live = new HashSet<uint>();
        foreach (var e in ProcessSnapshotCache.Snapshot) live.Add(e.Pid);
        lock (_seenLock)
        {
            if (_seenPids.Count == 0) return;
            _seenPids.RemoveWhere(p => !live.Contains(p));
        }
    }

    private void WorkLoop()
    {
        while (!_cts.IsCancellationRequested)
        {
            (uint Pid, string Path) item;
            try { item = _queue.Take(_cts.Token); }
            catch { return; }

            try
            {
                if (Whitelist != null && Whitelist.IsWhitelisted(item.Path))
                    continue;

                if (TryKnownBadHalt(item.Path, item.Pid))
                    continue;

                var v = Analyze(item.Path);
                if (v == null) continue;
                if (v.IsBlocker) { RespondToRunning(v, item.Pid); RecordBlockerFingerprint(v); }
                else if (v.IsWatchable) Report(v, item.Pid, "reported, below the halt threshold");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[ZERODAY] work error: {ex.Message}");
            }

            // One image read + header parse per 400 ms: a fork-bomb of new processes cannot turn
            // into a disk saturation storm.
            try { _cts.Token.WaitHandle.WaitOne(400); }
            catch { return; }
        }
    }

    /// <summary>
    /// An already-confirmed identity needs no heuristics: freeze the running image and skip the
    /// structural pass. Only the exact sha256 tier acts here — weaker tiers are reported by the
    /// file pipeline, never used to freeze a live process.
    /// </summary>
    private bool TryKnownBadHalt(string path, uint pid)
    {
        if (Fingerprints == null || Fingerprints.Count == 0) return false;
        var hit = Fingerprints.Lookup(FileFingerprinter.Sha256Of(path), "", "", "");
        if (hit is not { } known || known.Kind != "exact") return false;

        string reason = $"known-bad fingerprint {Short(known.Entry.Sha256)} ({known.Entry.Source})";
        int halted = SafeProcessKiller.HaltOnly(pid, reason);
        Interlocked.Increment(ref _halted);
        EventBus.Detection("malware", "high", "Known-bad file executed",
            $"{Path.GetFileName(path)} (pid {pid}) matches a recorded known-bad fingerprint, so the process was frozen — not deleted. Thaw it from the SubKit card if the record is wrong. {reason}",
            pid);
        EventBus.Status($"zeroday_knownbad pid={pid} halted={halted} sha={Short(known.Entry.Sha256)}");
        return true;
    }

    private void RecordBlockerFingerprint(ZeroDayVerdict v)
    {
        try
        {
            if (Fingerprints == null) return;
            var fp = FileFingerprinter.Compute(v.FilePath, "zeroday", $"score {v.Score}: {v.SignalText}");
            if (fp == null) return;
            if (Fingerprints.Add(fp))
            {
                Console.WriteLine($"[FP] recorded zero-day blocker sha256={Short(fp.Sha256)} imphash={Short(fp.ImportHash)} :: {v.FilePath}");
                EventBus.Status($"fingerprint_recorded source=zeroday sha={Short(fp.Sha256)}");
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[FP] record failed: {ex.Message}");
        }
    }

    private static string Short(string s) => s.Length <= 16 ? s : s[..16];

    private void RespondToRunning(ZeroDayVerdict v, uint pid)
    {
        string reason = $"zero-day file verdict score {v.Score}: {v.SignalText}";
        Report(v, pid, "blocker verdict");

        int halted = SafeProcessKiller.HaltOnly(pid, reason);
        if (halted > 0)
        {
            Interlocked.Increment(ref _halted);
            EventBus.Detection("malware", "shield", "Unknown file halted",
                $"{Path.GetFileName(v.FilePath)} (pid {pid}) scored {v.Score} with no signature and no cloud verdict, so the process was frozen — not deleted. Thaw it from the SubKit card if the verdict is wrong. Signals: {v.SignalText}",
                pid);
            EventBus.Status($"zeroday_halt pid={pid} score={v.Score} halted={halted}");
        }
        else
        {
            EventBus.Status($"zeroday_halt_refused pid={pid} score={v.Score}");
        }
    }

    private void Report(ZeroDayVerdict v, uint pid, string note)
    {
        string sev = v.IsBlocker ? "high" : "medium";
        Console.WriteLine($"[ZERODAY] {v.Summary} pid={pid} ({note})");
        EventBus.Detection("malware", sev, "Signature-free file analysis",
            $"{Path.GetFileName(v.FilePath)} — {v.Summary} [{note}]", pid);
    }

    // ---------------------------------------------------------------- helpers

    private static bool IsUserWritableDropLocation(string lowerPath)
    {
        string temp = Path.GetTempPath().ToLowerInvariant();
        string appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData).ToLowerInvariant();
        string local = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData).ToLowerInvariant();
        string dl = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "downloads").ToLowerInvariant();
        return lowerPath.StartsWith(temp)
            || lowerPath.StartsWith(local)
            || lowerPath.StartsWith(appData)
            || lowerPath.StartsWith(dl)
            || lowerPath.Contains("\\programdata\\")
            || lowerPath.Contains("\\public\\");
    }

    private static string? LureExtension(string lowerBaseName)
    {
        // "invoice.pdf.exe", "report.docx.exe" — a document name that ends in a runnable tail.
        string[] docs = { ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".jpg", ".jpeg", ".png", ".txt", ".zip", ".iso" };
        foreach (var run in new[] { ".exe", ".scr", ".com", ".pif", ".vbs", ".js", ".bat", ".cmd", ".jar" })
        {
            if (!lowerBaseName.EndsWith(run)) continue;
            string stem = lowerBaseName.Substring(0, lowerBaseName.Length - run.Length);
            foreach (var d in docs)
                if (stem.EndsWith(d)) return stem.Substring(stem.LastIndexOf('.')) + run;
        }
        return null;
    }

    private static bool RandomLookingStem(string? stem)
    {
        if (string.IsNullOrEmpty(stem) || stem.Length < 8) return false;
        int alnum = 0, digits = 0;
        foreach (char c in stem)
        {
            if (char.IsLetterOrDigit(c)) alnum++;
            if (char.IsDigit(c)) digits++;
        }
        if (alnum < 8) return false;
        double ratio = (double)digits / alnum;
        // Machine names are either hex-ish or a long consonant run with no separators.
        bool hexish = stem.All(c => Uri.IsHexDigit(c)) && stem.Length >= 8;
        return hexish || (ratio > 0.35 && !stem.Contains('-') && !stem.Contains('_'));
    }

    private static int CountPeMagic(byte[] b, int start, int length)
    {
        int hits = 0;
        int end = start + Math.Max(0, length - 2);
        for (int i = start; i < end && hits < 4; i++)
            if (b[i] == 0x4D && b[i + 1] == 0x5A && i + 0x40 < b.Length && ReadI32(b, i + 0x3C) is > 0 and < 0x400)
                hits++;
        return hits;
    }

    private static int CountAscii(byte[] b, string needle)
    {
        byte[] n = Encoding.ASCII.GetBytes(needle);
        int hits = 0;
        for (int i = 0; i + n.Length <= b.Length; i++)
        {
            bool ok = true;
            for (int j = 0; j < n.Length; j++)
                if (b[i + j] != n[j]) { ok = false; break; }
            if (ok) hits++;
            if (hits >= 8) break;
        }
        return hits;
    }

    private static bool ReadImports(byte[] b, int ddStart, uint[] va, uint[] vsz, uint[] raw, uint[] rawPtr,
        int nSections, bool pe32Plus, List<string> dlls, HashSet<string> funcs)
    {
        if (ddStart + 8 > b.Length) return false;
        int impRva = (int)ReadU32(b, ddStart);
        int impOff = RvaToOffset(va, raw, rawPtr, nSections, (uint)impRva);
        if (impOff <= 0 || impOff + 20 > b.Length) return false;

        int thunkSize = pe32Plus ? 8 : 4;
        ulong ordinalBit = pe32Plus ? (1UL << 63) : (1UL << 31);

        for (int desc = 0; desc < 64; desc++)
        {
            int o = impOff + desc * 20;
            if (o + 20 > b.Length) return desc > 0;
            uint oft = ReadU32(b, o);
            uint nameRva = ReadU32(b, o + 12);
            uint ft = ReadU32(b, o + 16);
            if (oft == 0 && ft == 0 && nameRva == 0) return true;

            int nameOff = RvaToOffset(va, raw, rawPtr, nSections, nameRva);
            string dllName = nameOff > 0 ? ReadName(b, nameOff, 64) : string.Empty;
            if (dllName.Length > 0) dlls.Add(dllName);

            uint table = oft != 0 ? oft : ft;
            int tOff = RvaToOffset(va, raw, rawPtr, nSections, table);
            if (tOff <= 0) continue;

            for (int k = 0; k < 4096; k++)
            {
                int to = tOff + k * thunkSize;
                if (to + thunkSize > b.Length) break;
                ulong val = pe32Plus ? ReadU64(b, to) : ReadU32(b, to);
                if (val == 0) break;
                if ((val & ordinalBit) != 0) continue;
                int hnOff = RvaToOffset(va, raw, rawPtr, nSections, (uint)val);
                if (hnOff <= 0 || hnOff + 2 >= b.Length) continue;
                string fn = ReadName(b, hnOff + 2, 128);
                if (fn.Length > 0) funcs.Add(fn);
            }
        }
        return true;
    }

    private static int SectionOf(uint[] va, uint[] vsz, uint rva)
    {
        for (int i = 0; i < va.Length; i++)
        {
            if (va[i] == 0) continue;
            uint size = Math.Max(vsz[i], 1u);
            if (rva >= va[i] && rva < va[i] + size) return i;
        }
        return -1;
    }

    private static int RvaToOffset(uint[] va, uint[] raw, uint[] rawPtr, int nSections, uint rva)
    {
        if (rva == 0) return -1;
        for (int i = 0; i < nSections; i++)
        {
            if (va[i] == 0 || rawPtr[i] == 0) continue;
            if (rva >= va[i] && rva < va[i] + Math.Max(raw[i], 1u))
            {
                long off = rawPtr[i] + (rva - va[i]);
                return off > int.MaxValue ? -1 : (int)off;
            }
        }
        return -1;
    }

    private static double SectionEntropy(byte[] b, uint ptr, uint size)
    {
        if (ptr == 0 || size == 0 || ptr >= b.Length) return 0;
        int len = (int)Math.Min(size, (uint)Math.Min(MaxEntropySample, b.Length - (long)ptr));
        if (len < 64) return 0;
        var freq = new int[256];
        for (int i = 0; i < len; i++) freq[b[ptr + i]]++;
        double e = 0;
        for (int i = 0; i < 256; i++)
        {
            if (freq[i] == 0) continue;
            double p = (double)freq[i] / len;
            e -= p * Math.Log2(p);
        }
        return e;
    }

    private static string Preview(HashSet<string> funcs, HashSet<string> group)
    {
        var sb = new StringBuilder();
        int n = 0;
        foreach (var f in group)
        {
            if (!funcs.Contains(f)) continue;
            if (n++ > 0) sb.Append(',');
            sb.Append(f);
            if (n >= 3) break;
        }
        return sb.ToString();
    }

    private static ushort ReadU16(byte[] b, int o) => o + 2 <= b.Length ? (ushort)(b[o] | (b[o + 1] << 8)) : (ushort)0;
    private static uint ReadU32(byte[] b, int o) => o + 4 <= b.Length ? (uint)(b[o] | (b[o + 1] << 8) | (b[o + 2] << 16) | (b[o + 3] << 24)) : 0u;
    private static int ReadI32(byte[] b, int o) => (int)ReadU32(b, o);
    private static ulong ReadU64(byte[] b, int o) => o + 8 <= b.Length ? ReadU32(b, o) | ((ulong)ReadU32(b, o + 4) << 32) : 0UL;

    private static string ReadName(byte[] b, int o, int maxLen)
    {
        if (o < 0 || o >= b.Length) return string.Empty;
        int end = Math.Min(b.Length, o + maxLen);
        int i = o;
        while (i < end && b[i] != 0) i++;
        try { return Encoding.ASCII.GetString(b, o, i - o); }
        catch { return string.Empty; }
    }
}
