using System;
using System.Buffers;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using System.Threading;

namespace NexusAV.Engine;

/// <summary>
/// User-mode "Active Guardian": a 250 ms command-line / process-integrity guard that
/// inspects every live script interpreter (powershell, cmd, wscript, mshta, ...), reads its
/// real command line from the PEB, matches it against ATT&amp;CK rules with <see cref="ReadOnlySpan{T}"/>
/// (no per-event heap allocation on the hot path) and terminates offending processes, emitting a
/// guard event that the GUI renders as an actionable notification.
///
/// It is fed three ways: a 250 ms EnumProcesses new-pid detector (works without admin, catches
/// short-lived <c>cmd /c ...</c> interpreters), a 1 s Toolhelp-based backstop snapshot, plus a
/// near-real-time suspect queue pushed by <see cref="EtwSubscriber"/> on ETW process-create
/// events when the engine runs elevated.
/// </summary>
public sealed unsafe class ActiveGuardian : IDisposable
{
    private const int PollIntervalMs = 250;
    private const int MaxInterpretersPerPass = 2048;
    private const int MaxCmdChars = 32_768;

    // PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ
    private const uint QueryLimitedAccess = 0x1000;
    private const uint VmReadAccess = 0x0010;

    private readonly Storyteller _storyteller;
    private readonly uint _enginePid;

    // Reusable command-line scratch buffer (ASCII-lowercased in place). Single reader thread.
    private readonly char[] _cmdBuf = new char[MaxCmdChars];

    // Near-real-time work queue fed by ETW process-create (interpreters only).
    // Carries the image name from the ETW event so Evaluate never needs its own snapshot.
    private readonly ConcurrentQueue<(uint pid, string img)> _suspects = new();

    // Fast new-pid detection (works unprivileged): EnumProcesses runs every loop pass,
    // and any pid absent from the previous pass is a brand-new process evaluated at once.
    private readonly uint[] _pidBuf = new uint[8192];
    private readonly HashSet<uint> _knownPids = new();

    // Guarded interpreters whose PEB could not be read while the process was still alive
    // (ACL/elevation). Counted so the GUI can surface the visibility gap honestly.
    private readonly HashSet<uint> _unreadablePids = new();

    // Deduplication of reported (pid, rule, command line) — see Evaluate.
    private readonly Dictionary<uint, (string rule, int hash)> _reportedHits = new();

    // Allow state. Written from the command thread, read from the loop thread.
    private readonly ConcurrentDictionary<uint, byte> _onceAllowed = new();
    private readonly ConcurrentDictionary<string, byte> _allowedRules = new(StringComparer.OrdinalIgnoreCase);
    private readonly ConcurrentDictionary<string, byte> _allowedImages = new(StringComparer.OrdinalIgnoreCase);

    // Cooldown per pid so we do not re-read the same command line on all 25 ticks/sec.
    private readonly Dictionary<uint, long> _lastReadStamp = new();
    private long _lastPurge;
    private volatile bool _enabled = true;

    private Thread? _thread;
    private int _disposed;

    public int TotalScanned;
    public int TotalBlocked;
    public int UnreadableTotal;

    public ActiveGuardian(Storyteller storyteller, uint enginePid)
    {
        _storyteller = storyteller;
        _enginePid = enginePid;
    }

    public void Start()
    {
        if (_thread != null || _disposed == 1) return;
        SelfTest();
        _thread = new Thread(Loop) { IsBackground = true, Name = "Nexus-ActiveGuardian", Priority = ThreadPriority.BelowNormal };
        _thread.Start();
    }

    /// <summary>
    /// Proof, not a claim: run the rule table over command lines that a normal user, developer or
    /// admin runs every day. A benign line that reaches a killable (high) match means one rule is
    /// broad enough to hit ordinary shells, so the engine says so out loud at startup instead of
    /// killing the operator's console later. Runs once, on the table only — no process is opened
    /// or touched.
    /// </summary>
    private void SelfTest()
    {
        int benignKillable = 0;
        foreach (string line in BenignSelfTest)
        {
            string lower = line.ToLowerInvariant();
            Rule? r = MatchRaw(new ReadOnlySpan<char>(lower.ToCharArray()), ImageOfCommandLine(lower));
            if (r == null) continue;
            if (string.Equals(r.Severity, "high", StringComparison.OrdinalIgnoreCase))
            {
                benignKillable++;
                Console.WriteLine($"[GUARD] SELF-TEST FAULT: benign command line would be killed by {r.Id} ({r.Technique}) :: {line}");
                EventBus.Status($"guard_selftest_fault rule={r.Id} line={line}");
            }
            else
            {
                Console.WriteLine($"[GUARD] self-test note: {r.Id} flags (not kills) a benign line :: {line}");
            }
        }

        Console.WriteLine($"[GUARD] self-test done benign_lines={BenignSelfTest.Length} killable_faults={benignKillable} rules={Rules.Length}");
        EventBus.Status($"guard_selftest benign={BenignSelfTest.Length} killable_faults={benignKillable} rules={Rules.Length}");
    }

    private static string ImageOfCommandLine(string lowerLine)
    {
        string head = lowerLine;
        int sp = head.IndexOf(' ');
        if (sp > 0) head = head.Substring(0, sp);
        int slash = head.LastIndexOfAny(new[] { '\\', '/' });
        if (slash >= 0) head = head.Substring(slash + 1);
        return head;
    }

    // Ordinary work on this machine. None of these may be terminated.
    private static readonly string[] BenignSelfTest =
    {
        @"c:\windows\system32\windowspowershell\v1.0\powershell.exe",
        @"powershell.exe",
        @"powershell.exe -noexit -command ""get-process | sort-object cpu -desc | select -first 10""",
        @"powershell.exe -noprofile -file c:\users\dev\projects\build.ps1",
        @"powershell.exe -command ""set-executionpolicy -scope currentuser bypass""",
        @"powershell.exe -command ""get-childitem c:\users\olgap\documents -recurse | measure-Object""",
        @"cmd.exe /c dir c:\users\olgap\documents",
        @"wscript.exe c:\users\olgap\desktop\login.vbs",
        @"certutil -verify c:\users\olgap\downloads\mycert.cer",
        @"reg query hkcu\software\myapp",
        @"sc query bits",
        @"netsh wlan show profiles",
        @"wmic cpu get loadpercentage",
        @"rundll32.exe shell32.dll,Control_RunDLL",
        @"mshta.exe c:\users\olgap\desktop\tool.hta",
        @"schtasks /create /tn NexusKeepAlive /tr c:\nexus\keepalive.exe /sc minute",
        // `-Encoding` starts with the same four characters as `-enc`; treating it as an encoded
        // command killed plain Get-Content/Set-Content work. These two lines guard that path.
        @"powershell.exe -command ""get-content c:\deploy\app.log -encoding utf8""",
        @"powershell.exe -command ""set-content c:\deploy\notes.txt -value ok -encoding ascii""",
    };

    public void SetEnabled(bool enabled) => _enabled = enabled;

    /// <summary>Called by the ETW subscriber when a new script-interpreter process starts.</summary>
    public void EnqueueSuspect(uint pid, string imageName)
    {
        if (pid != _enginePid) _suspects.Enqueue((pid, imageName));
    }

    public void AllowOnce(uint pid) => _onceAllowed.TryAdd(pid, 0);
    public void AllowRule(string ruleId) { if (!string.IsNullOrEmpty(ruleId)) _allowedRules.TryAdd(ruleId, 0); }
    public void AllowImage(string image) { if (!string.IsNullOrEmpty(image)) _allowedImages.TryAdd(image, 0); }

    /// <summary>True if <paramref name="imageName"/> is a script-capable interpreter we guard.</summary>
    public static bool IsGuardedImageName(string imageName)
    {
        if (string.IsNullOrEmpty(imageName)) return false;
        int slash = imageName.LastIndexOfAny(new[] { '\\', '/' });
        if (slash >= 0) imageName = imageName.Substring(slash + 1);
        if (imageName.EndsWith(".exe", StringComparison.OrdinalIgnoreCase))
            imageName = imageName.Substring(0, imageName.Length - 4);
        foreach (var g in GuardedImages)
            if (string.Equals(imageName, g, StringComparison.OrdinalIgnoreCase)) return true;
        return false;
    }

    private void Loop()
    {
        while (Volatile.Read(ref EngineState.ShuttingDown) == 0 && Volatile.Read(ref _disposed) == 0)
        {
            try
            {
                if (_enabled && Volatile.Read(ref EngineState.BypassMode) == 0)
                {
                    DetectNewProcesses();
                    DrainSuspects();
                    PollSnapshot();
                    PurgeStale();
                }
            }
            catch
            {
                // The guardian must never take down the detection engine.
            }

            Thread.Sleep(PollIntervalMs);
        }
    }

    /// <summary>
    /// Enumerates all PIDs every pass (~250 ms) and evaluates any pid that was not present in
    /// the previous pass. This is the primary real-time path when ETW is unavailable (engine
    /// not elevated): it catches short-lived interpreters like <c>cmd /c certutil ...</c> that
    /// die between two 1 s snapshots. One EnumProcesses call per pass — no per-process opens
    /// unless a genuinely new pid appears.
    /// </summary>
    private void DetectNewProcesses()
    {
        if (!EnumProcesses(_pidBuf, (uint)(_pidBuf.Length * sizeof(uint)), out uint cbNeeded)) return;
        int n = (int)(cbNeeded / sizeof(uint));
        if (n > _pidBuf.Length) n = _pidBuf.Length;

        for (int i = 0; i < n; i++)
        {
            uint pid = _pidBuf[i];
            if (pid != 0 && !_knownPids.Contains(pid)) CheckNewProcess(pid);
        }

        // Rebuild the known set every pass: a pid that dies and is later reused counts as new again.
        _knownPids.Clear();
        for (int i = 0; i < n; i++)
        {
            if (_pidBuf[i] != 0) _knownPids.Add(_pidBuf[i]);
        }
    }

    private void CheckNewProcess(uint pid)
    {
        if (ShouldSkip(pid)) return;
        string path = QueryImagePath(pid);
        if (path.Length == 0) return;
        if (IsGuardedImageName(path))
        {
            Evaluate(pid, force: true, BaseName(path));
            return;
        }
        CheckImageOrigin(pid, path);
    }

    private static string BaseName(string path)
    {
        int i = path.LastIndexOf('\\');
        return i >= 0 ? path.Substring(i + 1) : path;
    }

    private void DrainSuspects()
    {
        int budget = 64;
        while (budget-- > 0 && _suspects.TryDequeue(out var item))
        {
            if (ShouldSkip(item.pid)) continue;
            Evaluate(item.pid, force: true, item.img);
        }
    }

    private void PollSnapshot()
    {
        // Read the shared throttled snapshot instead of taking our own Toolhelp32 snapshot.
        // The old code snapshotted every process+thread at 25 Hz AND took a second full
        // snapshot per evaluated interpreter (QueryImageName) — a kernel-lock storm that
        // stalled the whole host. This poll is only a backstop now; ETW delivers new
        // interpreters near-real-time through the suspect queue.
        var snapshot = ProcessSnapshotCache.Snapshot;
        int seen = 0;
        for (int i = 0; i < snapshot.Count && seen < MaxInterpretersPerPass; i++)
        {
            var entry = snapshot[i];
            if (!IsGuardedImageName(entry.Name)) continue;
            seen++;
            uint pid = entry.Pid;
            if (ShouldSkip(pid)) continue;

            // Backstop cadence: only re-read a live interpreter every ~1s unless it's brand new.
            long now = MonotonicMs();
            if (_lastReadStamp.TryGetValue(pid, out long stamp) && now - stamp < 1000) continue;

            Evaluate(pid, force: false, entry.Name);
            _lastReadStamp[pid] = MonotonicMs();
        }
    }

    private bool ShouldSkip(uint pid)
    {
        if (pid == _enginePid || pid == 0 || pid == 4) return true;
        if (_onceAllowed.ContainsKey(pid)) return true;
        return false;
    }

    private void PurgeStale()
    {
        long now = MonotonicMs();
        if (now - _lastPurge < 5000) return;
        _lastPurge = now;

        // Remove cooldown entries for processes that no longer exist.
        List<uint>? toDrop = null;
        foreach (var kv in _lastReadStamp)
        {
            IntPtr h = OpenProcess(QueryLimitedAccess, false, kv.Key);
            if (h == IntPtr.Zero)
            {
                (toDrop ??= new List<uint>()).Add(kv.Key);
            }
            else
            {
                CloseHandle(h);
            }
        }
        if (toDrop != null)
        {
            foreach (var p in toDrop)
            {
                _lastReadStamp.Remove(p);
                _unreadablePids.Remove(p);
            }
        }

        // Cap the once-allow set so it cannot grow unbounded across a long session.
        if (_onceAllowed.Count > 4096) _onceAllowed.Clear();
    }

    private void Evaluate(uint pid, bool force, string knownImage)
    {
        string image = knownImage.Length > 0
            ? knownImage
            : (ProcessSnapshotCache.TryGetName(pid, out var cached) ? cached : string.Empty);
        if (image.Length == 0) return;
        string lowerImage = image.ToLowerInvariant();
        if (lowerImage.EndsWith(".exe")) lowerImage = lowerImage.Substring(0, lowerImage.Length - 4);
        if (_allowedImages.ContainsKey(lowerImage)) return;

        int len = ReadCommandLine(pid, _cmdBuf);
        if (len <= 0)
        {
            // Still alive but PEB unreadable (protected/elevated target, ACL): count it so
            // the UI can surface the visibility gap instead of missing threats silently.
            IntPtr probe = OpenProcess(QueryLimitedAccess, false, pid);
            if (probe != IntPtr.Zero)
            {
                CloseHandle(probe);
                if (_unreadablePids.Add(pid)) Interlocked.Increment(ref UnreadableTotal);
            }
            return;
        }

        TotalScanned++;

        // ASCII-lowercase the buffer in place so span matching needs no allocation.
        fixed (char* b = _cmdBuf)
        {
            for (int i = 0; i < len; i++)
            {
                char c = b[i];
                if (c >= 'A' && c <= 'Z') b[i] = (char)(c + 32);
            }
        }

        ReadOnlySpan<char> cmd = new(_cmdBuf, 0, len);

        Rule? hit = MatchRule(cmd, lowerImage);
        if (hit == null) return;
        if (_allowedRules.ContainsKey(hit.Id)) return;

        // Deduplicate: report each unique (pid, rule, command line) exactly once. Without
        // this, a long-lived interpreter matching a rule re-emitted a guard event on every
        // 1 s cooldown tick, flooding the GUI feed.
        int cmdHash = string.GetHashCode(new string(_cmdBuf, 0, Math.Min(len, 256)));
        lock (_reportedHits)
        {
            if (_reportedHits.TryGetValue(pid, out var prev) && prev.rule == hit.Id && prev.hash == cmdHash)
            {
                _lastReadStamp[pid] = MonotonicMs();
                return;
            }
            if (_reportedHits.Count > 4096) _reportedHits.Clear();
            _reportedHits[pid] = (hit.Id, cmdHash);
        }

        // Real detection. Record confidence via the Storyteller, then act.
        var (score, allowlisted, _, _) = _storyteller.ReportCommandThreat(pid, 0, image, hit.Id, hit.Weight);
        if (allowlisted)
        {
            EventBus.Guard(pid, 0, image, Trim(new string(_cmdBuf, 0, Math.Min(len, 800))),
                hit.Id, hit.Technique, hit.Severity, "allowlisted", QueryImagePath(pid), score);
            return;
        }

        string commandLine = Trim(new string(_cmdBuf, 0, Math.Min(len, 800)));
        string path = QueryImagePath(pid);

        // Terminate on high-severity matches, and whenever the Storyteller's cumulative risk score
        // crossed the reactive-kill threshold (>= 70) — a repeat medium offender accumulates there.
        // A LONE medium match still only flags: killing every "schtasks /create" caused
        // kill/respawn storms that stalled the host. The exception is a medium match with
        // independent corroboration (drop location, MOTW, bad signature, script-host parent) —
        // that is an attack chain, not an admin doing admin things.
        string corroboration = Corroborate(pid, lowerImage, path);
        bool shouldKill = string.Equals(hit.Severity, "high", StringComparison.OrdinalIgnoreCase)
            || score >= SafeProcessKiller.KillScoreThreshold
            || corroboration.Length > 0;

        if (corroboration.Length > 0)
        {
            Console.WriteLine($"[GUARDIAN] corroboration pid={pid} img={image} rule={hit.Id} evidence={corroboration}");
            EventBus.Status($"guard_corroboration pid={pid} rule={hit.Id} evidence={corroboration}");
        }

        string reason = $"guard rule {hit.Id} ({hit.Technique}) sev={hit.Severity}";
        if (corroboration.Length > 0) reason += $" +{corroboration}";

        bool terminated = shouldKill && SafeProcessKiller.Terminate(pid, reason, score);
        string action = terminated ? "terminated" : (shouldKill ? "kill-refused" : "flagged");
        if (terminated) Interlocked.Increment(ref TotalBlocked);

        EventBus.Guard(pid, 0, image, commandLine, hit.Id, hit.Technique, hit.Severity, action, path, score);
        Console.WriteLine($"[GUARDIAN] {action} pid={pid} img={image} rule={hit.Id} ({hit.Technique}) sev={hit.Severity} :: {commandLine}");

        // Remember so we don't repeatedly re-terminate a lingering handle.
        _lastReadStamp[pid] = MonotonicMs();
    }

    private static string Trim(string s)
    {
        // Collapse control chars so the event stays a single-line JSON-safe string.
        Span<char> tmp = stackalloc char[Math.Min(s.Length, 800)];
        int n = 0;
        foreach (char c in s)
        {
            if (n >= tmp.Length) break;
            tmp[n++] = c < 0x20 ? ' ' : c;
        }
        return new string(tmp.Slice(0, n));
    }

    private Rule? MatchRule(ReadOnlySpan<char> cmd, string lowerImage)
        => MatchCore(cmd, lowerImage, honorAllowlist: true);

    /// <summary>Raw rule-table match, ignoring runtime allowlists. Used by the benign self-test.</summary>
    private Rule? MatchRaw(ReadOnlySpan<char> cmd, string lowerImage)
        => MatchCore(cmd, lowerImage, honorAllowlist: false);

    private Rule? MatchCore(ReadOnlySpan<char> cmd, string lowerImage, bool honorAllowlist)
    {
        foreach (var rule in Rules)
        {
            if (honorAllowlist && _allowedRules.ContainsKey(rule.Id)) continue;

            // If the rule scopes to a specific interpreter image, honor it.
            if (rule.ImageScope.Length > 0 && !ContainsImage(lowerImage, rule.ImageScope)) continue;

            bool all = true;
            foreach (string needle in rule.All)
            {
                if (cmd.IndexOf(needle.AsSpan(), StringComparison.Ordinal) < 0) { all = false; break; }
            }
            if (all) return rule;
        }
        return null;
    }

    private static bool ContainsImage(string lowerImage, string scope) => lowerImage.Contains(scope);

    // ── Process / memory helpers ───────────────────────────────────────────

    private static string QueryImagePath(uint pid)
    {
        IntPtr h = OpenProcess(QueryLimitedAccess, false, pid);
        if (h == IntPtr.Zero) return string.Empty;
        try
        {
            int cap = 1024;
            char* buf = stackalloc char[cap];
            uint len = (uint)cap;
            if (QueryFullProcessImageNameW(h, 0, buf, ref len) && len > 0)
                return new string(buf, 0, (int)len);
            return string.Empty;
        }
        finally { CloseHandle(h); }
    }

    /// <summary>
    /// Reads the live command line of <paramref name="pid"/> straight out of its PEB
    /// (ProcessBasicInformation -> PEB.ProcessParameters -> RTL_USER_PROCESS_PARAMETERS.CommandLine).
    /// Fills <paramref name="outBuf"/> (raw, NOT lowercased) and returns the char count, or 0.
    /// </summary>
    internal static int ReadCommandLine(uint pid, char[] outBuf)
    {
        IntPtr h = OpenProcess(QueryLimitedAccess | VmReadAccess, false, pid);
        if (h == IntPtr.Zero) return 0;
        try
        {
            ProcessBasicInformation pbi;
            int nt = NtQueryInformationProcess(h, 0, &pbi, sizeof(ProcessBasicInformation), null);
            if (nt != 0 || pbi.PebBaseAddress == IntPtr.Zero) return 0;

            // PEB.ProcessParameters is at offset 0x20 on x64.
            long pp;
            if (!Rpm(h, (byte*)pbi.PebBaseAddress + 0x20, &pp, 8)) return 0;
            if (pp == 0) return 0;

            // RTL_USER_PROCESS_PARAMETERS.CommandLine (UNICODE_STRING) at offset 0x70 on x64.
            UnicodeString64 us;
            if (!Rpm(h, (byte*)pp + 0x70, &us, sizeof(UnicodeString64))) return 0;

            int chars = us.Length / 2;
            if (chars <= 0 || us.Buffer == 0) return 0;
            if (chars > outBuf.Length) chars = outBuf.Length;

            fixed (char* dst = outBuf)
            {
                if (!ReadProcessMemory(h, (void*)us.Buffer, dst, (IntPtr)(chars * 2), out IntPtr read))
                    return 0;
                return (int)read / 2;
            }
        }
        catch { return 0; }
        finally { CloseHandle(h); }
    }

    private static bool Rpm(IntPtr h, void* addr, void* dst, int size)
        => ReadProcessMemory(h, addr, dst, (IntPtr)size, out _) && true;

    /// <summary>
    /// Quiet-dropper heuristic for non-interpreter images: an executable started out of a
    /// risky location (temp/downloads/public/programdata) that either carries a
    /// Mark-of-the-Web zone tag (was downloaded) or was spawned by a script interpreter —
    /// and is not validly signed. Flag-only: installers and dev tools legitimately land in
    /// temp, so this never kills; the popup lets the user decide.
    /// </summary>
    private void CheckImageOrigin(uint pid, string path)
    {
        string lower = path.ToLowerInvariant();
        if (!HasExecutableExtension(lower)) return;
        if (!IsRiskyOrigin(lower)) return;

        string baseName = BaseName(path);
        string lowerBase = baseName.ToLowerInvariant();
        if (lowerBase.EndsWith(".exe")) lowerBase = lowerBase.Substring(0, lowerBase.Length - 4);
        if (_allowedImages.ContainsKey(lowerBase) || _allowedRules.ContainsKey("ORIGIN-TEMP")) return;

        int pathHash = StringComparer.OrdinalIgnoreCase.GetHashCode(path);
        lock (_reportedHits)
        {
            if (_reportedHits.TryGetValue(pid, out var prev) && prev.rule == "ORIGIN-TEMP" && prev.hash == pathHash) return;
            if (_reportedHits.Count > 4096) _reportedHits.Clear();
            _reportedHits[pid] = ("ORIGIN-TEMP", pathHash);
        }

        bool downloaded = HasZoneTag(path);
        uint parent = GetParentPid(pid);
        string parentName = parent != 0 && ProcessSnapshotCache.TryGetName(parent, out var pn) ? pn : string.Empty;
        bool interpreterParent = parentName.Length > 0 && IsGuardedImageName(parentName);
        if (!downloaded && !interpreterParent) return;

        var (sigState, _) = WinTrust.VerifyFile(path);
        if (sigState == SignatureState.MicrosoftSigned || sigState == SignatureState.TrustedPublisher) return;

        TotalScanned++;
        EventBus.Guard(pid, parent, baseName,
            $"path={path} parent={parentName} downloaded={(downloaded ? 1 : 0)} sig={sigState}",
            "ORIGIN-TEMP", "T1204.002", "medium", "flagged", path, 30);
        Console.WriteLine($"[GUARDIAN] flagged pid={pid} img={baseName} rule=ORIGIN-TEMP (T1204.002) sev=medium :: {path} parent={parentName} motw={(downloaded ? 1 : 0)} sig={sigState}");
        _lastReadStamp[pid] = MonotonicMs();
    }

    // LOLBins an attacker abuses through a script host. A script interpreter launching one of
    // these is normal for admins too, so this never triggers on its own — it only escalates a
    // command line that ALREADY matched a rule.
    private static readonly HashSet<string> LolBinChildren = new(StringComparer.OrdinalIgnoreCase)
    {
        "reg", "certutil", "bitsadmin", "schtasks", "net", "net1", "rundll32", "regsvr32",
        "msbuild", "installutil", "mshta", "wmic", "vssadmin", "esentutl", "ntdsutil",
        "wscript", "cscript", "msiexec", "sc", "taskkill", "wevtutil"
    };

    /// <summary>
    /// Independent evidence that a matched command line is a real attack rather than an admin
    /// doing admin things. Every source is a direct observation (file on disk, signature state,
    /// parent link from the process table) — never an inference from the command line itself, so
    /// it cannot simply echo the rule that already fired.
    /// </summary>
    private string Corroborate(uint pid, string lowerImage, string path)
    {
        if (path.Length > 0 && !IsTrustedRoot(path))
        {
            // 1. Downloaded from the internet (Mark-of-the-Web alternate data stream).
            if (HasZoneTag(path)) return "mark-of-the-web";
            // 2. Running from a user-writable drop location where installed tooling never lives.
            if (IsRiskyOrigin(path.ToLowerInvariant())) return "drop-location";
        }

        if (_storyteller.Processes.TryGetValue(pid, out var node))
        {
            // 3. Signature state. Invalid/untrusted is positive evidence of tampering; plain
            //    Unsigned is too weak on its own (plenty of legitimate tooling is unsigned).
            _storyteller.VerifyAndAttachSignature(pid);
            if (node.SigState == SignatureState.Invalid) return "invalid-signature";
            if (node.SigState == SignatureState.Untrusted) return "untrusted-signature";

            // 4. Script host -> LOLBin child: a real chain shape whose parent link comes from the
            //    process table, not from the text we matched.
            uint parent = node.ParentPid != 0 ? node.ParentPid : GetParentPid(pid);
            if (parent != 0 && parent != 4 && LolBinChildren.Contains(lowerImage) &&
                ProcessSnapshotCache.TryGetName(parent, out var parentName) &&
                IsGuardedImageName(parentName))
                return $"script-host-parent:{parentName}";
        }

        return string.Empty;
    }

    /// <summary>Roots where a flagged binary is expected to live (installed apps, Windows, our own data dir).</summary>
    private static bool IsTrustedRoot(string path)
    {
        string lower = path.ToLowerInvariant();
        return lower.Contains("\\program files\\") || lower.Contains("\\program files (x86)\\") ||
               lower.Contains("\\windows\\system32\\") || lower.Contains("\\windows\\syswow64\\") ||
               lower.Contains("\\programdata\\nexusxdr\\");
    }

    private static bool HasExecutableExtension(string lowerPath) =>
        lowerPath.EndsWith(".exe") || lowerPath.EndsWith(".scr") || lowerPath.EndsWith(".com") ||
        lowerPath.EndsWith(".bat") || lowerPath.EndsWith(".cmd") || lowerPath.EndsWith(".js") ||
        lowerPath.EndsWith(".jse") || lowerPath.EndsWith(".vbs") || lowerPath.EndsWith(".vbe") ||
        lowerPath.EndsWith(".wsf") || lowerPath.EndsWith(".hta") || lowerPath.EndsWith(".ps1");

    private static bool IsRiskyOrigin(string lowerPath) =>
        lowerPath.Contains("\\appdata\\local\\temp\\") ||
        lowerPath.Contains("\\windows\\temp\\") ||
        lowerPath.Contains("\\downloads\\") ||
        lowerPath.Contains("\\users\\public\\") ||
        lowerPath.Contains("\\programdata\\");

    private static bool HasZoneTag(string path)
    {
        try
        {
            using var fs = new FileStream(path + ":Zone.Identifier", FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            return fs.Length > 0;
        }
        catch { return false; }
    }

    private static uint GetParentPid(uint pid)
    {
        IntPtr h = OpenProcess(QueryLimitedAccess, false, pid);
        if (h == IntPtr.Zero) return 0;
        try
        {
            ProcessBasicInformation pbi;
            if (NtQueryInformationProcess(h, 0, &pbi, sizeof(ProcessBasicInformation), null) != 0) return 0;
            return (uint)pbi.InheritedFromUniqueProcessId;
        }
        finally { CloseHandle(h); }
    }

    private static long MonotonicMs() => Environment.TickCount64;

    public void Dispose()
    {
        if (Interlocked.CompareExchange(ref _disposed, 1, 0) != 0) return;
        try { _thread?.Join(200); } catch { }
    }

    // ── Rule table (fully implemented; every field used) ───────────────────

    private sealed class Rule
    {
        public readonly string Id;
        public readonly string Technique;
        public readonly string Severity;
        public readonly string ImageScope;
        public readonly string[] All;
        public readonly int Weight;

        public Rule(string id, string technique, string severity, string imageScope, int weight, params string[] all)
        {
            Id = id; Technique = technique; Severity = severity; ImageScope = imageScope; Weight = weight; All = all;
        }
    }

    private static readonly Rule[] Rules =
    {
        new("PS-ENCODED", "T1027", "high", "powershell", 40, "-enc ", "command"),
        new("PS-ENCODED2", "T1027", "high", "powershell", 40, "-encodedcommand"),
        new("PS-B64-ASM", "T1140", "high", "powershell", 40, "frombase64string", "assembly"),
        new("PS-DOWNLOAD", "T1059.001", "high", "powershell", 35, "downloadstring"),
        new("PS-DOWNLOADFILE", "T1059.001", "high", "powershell", 35, "downloadfile"),
        new("PS-IEX", "T1059.001", "medium", "powershell", 30, "invoke-expression"),
        new("PS-IEX2", "T1059.001", "medium", "powershell", 30, "iex "),
        new("PS-IWR-PIPE", "T1105", "high", "powershell", 35, "invoke-webrequest", "|", "iex"),
        new("PS-IRMPROXY", "T1090.003", "medium", "powershell", 20, "invoke-restmethod", "proxy"),
        new("PS-AMSI-BYPASS", "T1562.001", "high", "powershell", 45, "amsiutils"),
        new("PS-AMSI-INIT", "T1562.001", "high", "powershell", 45, "amsiinitfailed"),
        new("PS-DEFENDER-DISABLE", "T1562.001", "high", "powershell", 50, "set-mppreference", "-disablerealtimemonitoring"),
        new("PS-REFLECT-LOAD", "T1620", "high", "powershell", 40, "reflection.assembly]::load"),
        new("PS-ADDTYPE", "T1027", "medium", "powershell", 20, "add-type", "virtualalloc"),
        new("PS-TCPCLIENT", "T1059.001", "high", "powershell", 35, "net.sockets.tcpclient"),
        new("PS-MIMIKATZ", "T1003.001", "high", "powershell", 50, "invoke-mimikatz"),
        new("PS-LSASS-DUMP", "T1003.001", "high", "powershell", 50, "lsass", "minidump"),
        new("PS-WMI-EXEC", "T1047", "medium", "powershell", 25, "invoke-wcimethod"),
        new("PS-PERSIST-RUN", "T1547.001", "high", "powershell", 35, "currentversion\\run"),
        new("PS-HIDDEN-WSHORT", "T1564.003", "medium", "powershell", 25, "-w hidden"),
        new("PS-HIDDEN-WLONG", "T1564.003", "medium", "powershell", 25, "-windowstyle hidden"),
        new("CMD-CERTUTIL-DECODE", "T1140", "medium", "cmd", 25, "certutil", "-decode"),
        new("CMD-CERTUTIL-DL", "T1105", "high", "cmd", 35, "certutil", "-urlcache"),
        new("CMD-BITSADMIN", "T1197", "medium", "cmd", 25, "bitsadmin", "/transfer"),
        new("CMD-SCHTASKS", "T1053.005", "medium", "cmd", 20, "schtasks", "/create"),
        new("CMD-WMIC-CREATE", "T1047", "medium", "cmd", 25, "wmic", "process", "create"),
        new("CMD-RUN-PERSIST", "T1547.001", "high", "cmd", 35, "reg", "add", "\\run"),
        new("CMD-DISABLE-AV", "T1562.001", "high", "cmd", 45, "sc", "stop", "windefend"),
        new("MSHTA-JS", "T1218.005", "high", "mshta", 40, "javascript:"),
        new("MSHTA-VBS", "T1218.005", "high", "mshta", 40, "vbscript:"),
        new("MSHTA-HTTP", "T1218.005", "high", "mshta", 40, "http"),
        new("REGSVR32-SQUIBLY", "T1218.010", "high", "regsvr32", 45, "/i:http", "scrobj"),
        new("RUNDLL-JS", "T1218.011", "medium", "rundll32", 30, "javascript:"),
        new("SCRIPT-WS-COMPILE", "T1218.007", "medium", "wscript", 20, ".wsc"),
        new("INSTALLUTIL-UNLOCK", "T1218.004", "medium", "installutil", 25, "/logfile="),

        // Cross-image payload patterns: catches wrapper chains like `cmd /c powershell -enc ...`
        // that would otherwise dodge the per-image scoped rules above.
        new("PS-ENCODED-ANY", "T1027", "high", "", 40, "powershell", "-enc "),

        // Credential dumping (T1003 family)
        new("LSASS-COMsvcs", "T1003.001", "high", "", 50, "comsvcs", "minidump"),
        new("LSASS-PROCDUMP-CMD", "T1003.001", "high", "cmd", 45, "procdump", "lsass"),
        new("LSASS-PROCDUMP-PS", "T1003.001", "high", "powershell", 45, "procdump", "lsass"),
        new("SAM-RESAVE-CMD", "T1003.002", "high", "cmd", 45, "reg", "save", "hklm\\sam"),
        new("SAM-RESAVE-PS", "T1003.002", "high", "powershell", 45, "reg", "save", "hklm\\sam"),
        new("SAM-REXPORT-CMD", "T1003.002", "high", "cmd", 45, "reg", "export", "hklm\\sam"),
        new("SAM-REXPORT-PS", "T1003.002", "high", "powershell", 45, "reg", "export", "hklm\\sam"),
        new("SEC-RESAVE-CMD", "T1003.002", "high", "cmd", 45, "reg", "save", "hklm\\security"),
        new("SYS-RESAVE-CMD", "T1003.002", "high", "cmd", 45, "reg", "save", "hklm\\system"),

        // Ransomware precursor: shadow copy / backup destruction (T1490)
        new("VSS-DEL-CMD", "T1490", "high", "cmd", 45, "vssadmin", "delete", "shadows"),
        new("VSS-DEL-PS", "T1490", "high", "powershell", 45, "vssadmin", "delete", "shadows"),
        new("WBADMIN-DEL-CMD", "T1490", "medium", "cmd", 30, "wbadmin", "delete"),

        // Defense evasion
        new("WEVT-CL-CMD", "T1070.001", "medium", "cmd", 25, "wevtutil", " cl "),
        new("WEVT-CL-PS", "T1070.001", "medium", "powershell", 25, "wevtutil", " cl "),
        new("FW-DISABLE-CMD", "T1562.004", "medium", "cmd", 25, "netsh", "advfirewall", "set"),
        new("FW-DISABLE-PS", "T1562.004", "medium", "powershell", 25, "netsh", "advfirewall", "set"),
        new("BCDEDIT-SET", "T1542.001", "medium", "cmd", 25, "bcdedit", "/set"),

        // Execution / persistence via services and remote tools
        new("SC-BINPATH", "T1543.003", "medium", "cmd", 25, "sc ", "binpath"),
        new("SC-EXE-BINPATH", "T1543.003", "medium", "cmd", 25, "sc.exe", "binpath"),
        new("SC-BINPATH-PS", "T1543.003", "medium", "powershell", 25, "sc ", "binpath"),
        new("PSEXEC-CMD", "T1569.002", "medium", "cmd", 30, "psexec"),
        new("PSEXEC-PS", "T1569.002", "medium", "powershell", 30, "psexec"),
        new("NET-USER-ADD", "T1136.001", "medium", "cmd", 25, "net", "user", "/add"),
        new("NET-LOCALGROUP-ADD", "T1136.001", "medium", "cmd", 25, "net", "localgroup", "/add"),

        // Downloads (T1105)
        new("CURL-DL-CMD", "T1105", "medium", "cmd", 25, "curl", "http"),
        new("CURL-DL-PS", "T1105", "medium", "powershell", 25, "curl", "http"),
        new("IWR-OUTFILE-PS", "T1105", "medium", "powershell", 25, "invoke-webrequest", "outfile"),

        // ── Quiet LOLBin coverage: direct-image invocations (no cmd wrapper) ───
        new("CERTUTIL-DL-IMG", "T1105", "high", "certutil", 35, "urlcache"),
        new("CERTUTIL-URL-IMG", "T1105", "high", "certutil", 35, "http"),
        new("CERTUTIL-DECODE-IMG", "T1140", "medium", "certutil", 25, "-decode"),
        new("BITSADMIN-IMG", "T1197", "medium", "bitsadmin", 25, "/transfer"),
        new("MSIEXEC-HTTP", "T1218.007", "medium", "msiexec", 30, "http"),
        new("MAVINJECT", "T1055.002", "high", "mavinject", 45, "inject"),
        new("PCALUA-EXEC", "T1202", "medium", "pcalua", 25, "-a"),
        new("FORFILES-EXEC", "T1202", "medium", "forfiles", 25, "/c"),
        new("EXPAND-REMOTE", "T1105", "medium", "expand", 25, "http"),
        new("ESENTUTL-VSS", "T1003.003", "medium", "esentutl", 25, "vss"),
        new("NTDSUTIL-IFM", "T1003.003", "high", "ntdsutil", 45, "ifm"),
        new("SCHTASKS-IMG", "T1053.005", "medium", "schtasks", 20, "/create"),
        new("REG-RUN-ADD", "T1547.001", "high", "reg", 35, "add", "\\run"),
        new("REG-DEFENDER-DEL", "T1562.001", "high", "reg", 40, "delete", "defender"),
        new("SC-DEFENDER-STOP", "T1562.001", "high", "sc", 40, "stop", "windefend"),
        new("SC-DEFENDER-CONFIG", "T1562.001", "high", "sc", 40, "config", "windefend"),
        new("NETSH-PORTPROXY", "T1090", "medium", "netsh", 25, "portproxy", "add"),
        new("VSSADMIN-IMG", "T1490", "high", "vssadmin", 45, "delete", "shadows"),
        new("WBADMIN-IMG", "T1490", "medium", "wbadmin", 30, "delete"),
        new("WEVTUTIL-IMG", "T1070.001", "medium", "wevtutil", 25, " cl "),
        new("BCDEDIT-IMG", "T1542.001", "medium", "bcdedit", 25, "/set"),
        new("CURL-DL-OUT", "T1105", "medium", "curl", 25, "-o", "http"),
        new("WMIC-PROCESS-CALL", "T1047", "medium", "wmic", 25, "process", "call", "create"),

        // ── PowerShell quiet techniques (flag-level unless truly destructive) ──
        new("PS-EP-BYPASS", "T1562.001", "medium", "powershell", 30, "executionpolicy", "bypass"),
        new("PS-EXCL-ADD", "T1562.001", "medium", "powershell", 30, "add-mppreference", "exclusion"),
        new("PS-EXCL-PATH", "T1562.001", "medium", "powershell", 30, "-exclusionpath"),
        new("PS-DEFENDER-OFF", "T1562.001", "high", "powershell", 50, "set-mppreference", "disable"),
        new("PS-WMI-PERSIST", "T1546.003", "high", "powershell", 45, "commandlineeventconsumer"),
        new("PS-WMI-PERSIST2", "T1546.003", "high", "powershell", 45, "activescripteventconsumer"),
        new("PS-BITS-START", "T1197", "medium", "powershell", 25, "start-bitstransfer"),
        new("PS-XMLHTTP", "T1105", "medium", "powershell", 25, "xmlhttp"),
        new("PS-WINRS", "T1021.006", "medium", "powershell", 25, "enter-pssession"),
        new("PS-TEMP-SCRIPT", "T1059.001", "medium", "powershell", 30, "\\temp\\", ".ps1"),
        new("PS-TEMP-EXE", "T1204.002", "medium", "powershell", 30, "\\temp\\", ".exe"),
        new("PS-DL-EXE", "T1204.002", "medium", "powershell", 30, "\\downloads\\", ".exe"),
        new("PS-COPY-STARTUP", "T1547.001", "medium", "powershell", 30, "copy-item", "\\startup\\"),
        new("PS-NANODUMP", "T1003.001", "high", "powershell", 45, "nanodump"),
        new("PS-SECRETS-DUMP", "T1003.001", "high", "powershell", 45, "secretsdump"),
        new("PS-RUBEUS", "T1558", "high", "powershell", 45, "rubeus"),
        new("PS-SHARPHOUND", "T1087.002", "high", "powershell", 45, "sharphound"),

        // ── cmd-scoped quiet techniques ────────────────────────────────────────
        new("CMD-COPY-STARTUP", "T1547.001", "medium", "cmd", 30, "copy", "\\startup\\"),
        new("CMD-TEMP-EXE", "T1204.002", "medium", "cmd", 30, "\\temp\\", ".exe"),
        new("CMD-DL-EXE", "T1204.002", "medium", "cmd", 30, "\\downloads\\", ".exe"),
        new("CMD-NET-STOP-DEF", "T1562.001", "high", "cmd", 45, "net", "stop", "windefend"),
        new("CMD-WMIC-SHADOW", "T1490", "high", "cmd", 40, "shadowcopy", "delete"),
        new("CMD-FSUTIL-USN", "T1070.004", "medium", "cmd", 25, "fsutil", "deletejournal"),
        new("CMD-CIPHER-W", "T1485", "medium", "cmd", 25, "cipher", "/w"),
        new("CMD-SDELETE", "T1070.004", "medium", "cmd", 25, "sdelete"),
        new("CMD-AUDITPOL-CLEAR", "T1562.002", "medium", "cmd", 25, "auditpol", "clear"),
        new("CMD-NSLOOKUP-TXT", "T1071.004", "medium", "cmd", 25, "nslookup", "-type=txt"),
        new("CMD-WINRS", "T1021.006", "medium", "cmd", 25, "winrs"),

        // ── rundll32 quiet chains ──────────────────────────────────────────────
        new("RUNDLL-TEMP", "T1218.011", "medium", "rundll32", 30, "\\temp\\"),
        new("RUNDLL-REMOTE", "T1218.011", "medium", "rundll32", 30, "http"),
    };

    // The set of base names (without .exe) that we treat as script-capable interpreters
    // OR as LOLBins worth command-line inspection. Direct invocations of the LOLBins below
    // (not wrapped in cmd) used to be invisible because only interpreters were read.
    private static readonly string[] GuardedImages =
    {
        "powershell", "powershell_ise", "pwsh", "cmd", "wscript", "cscript",
        "mshta", "rundll32", "regsvr32", "installutil", "regasm", "regsvc", "eventvwr",
        "certutil", "bitsadmin", "msiexec", "wmic", "mavinject", "pcalua", "forfiles",
        "expand", "esentutl", "ntdsutil", "schtasks", "reg", "sc", "netsh",
        "vssadmin", "wbadmin", "wevtutil", "bcdedit", "curl"
    };

    private static bool IsGuardedInterpreter(char* szExeFileFixed)
    {
        // szExeFile is a fixed MAX_PATH (260) char array; read it as a span without allocating.
        ReadOnlySpan<char> name = new(szExeFileFixed, 260);
        int term = name.IndexOf('\0');
        if (term >= 0) name = name.Slice(0, term);
        // strip .exe
        if (name.EndsWith(".exe", StringComparison.OrdinalIgnoreCase))
            name = name.Slice(0, name.Length - 4);

        foreach (var g in GuardedImages)
        {
            if (name.Equals(g.AsSpan(), StringComparison.OrdinalIgnoreCase)) return true;
        }
        return false;
    }

    // ── Interop ────────────────────────────────────────────────────────────

    [StructLayout(LayoutKind.Sequential)]
    private struct ProcessBasicInformation
    {
        public IntPtr ExitStatus;
        public IntPtr PebBaseAddress;
        public IntPtr AffinityMask;
        public IntPtr BasePriority;
        public IntPtr UniqueProcessId;
        public IntPtr InheritedFromUniqueProcessId;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    private struct UnicodeString64
    {
        public ushort Length;
        public ushort MaximumLength;
        private uint _pad;
        public ulong Buffer;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CloseHandle(IntPtr handle);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenProcess(uint access, bool inherit, uint processId);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool ReadProcessMemory(IntPtr process, void* baseAddress, void* buffer, IntPtr size, out IntPtr bytesRead);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool QueryFullProcessImageNameW(IntPtr process, uint flags, char* exeName, ref uint size);

    [DllImport("ntdll.dll")]
    private static extern int NtQueryInformationProcess(IntPtr process, int infoClass, ProcessBasicInformation* info, int length, int* returnLength);

    [DllImport("psapi.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool EnumProcesses(uint[] processIds, uint cb, out uint cbNeeded);
}
