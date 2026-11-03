using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Threading;

namespace NexusAV.Engine;

/// <summary>
/// Content-level script detection — the layer that sees what the Active Guardian cannot.
///
/// The guardian matches the COMMAND LINE of a process. An attack typed into an interactive shell,
/// delivered by a dropper, or run through Invoke-AtomicTest never appears there: the payload lives
/// inside the script. AMSI hands every script block to a scan provider before it executes, and
/// Windows mirrors those scans onto the Microsoft-Antimalware-Scan-Interface ETW provider. Reading
/// that provider yields the script text with no registry policy change, no AMSI provider
/// registration and no injection into other processes.
///
/// Threading: ETW dispatches on a single thread, so the callback only enqueues. Matching, scoring
/// and termination run on our own worker — a slow kill must never stall the ETW pipeline.
///
/// The act decision reuses the guardian's gate exactly: high severity, or cumulative Storyteller
/// score >= SafeProcessKiller.KillScoreThreshold. Everything else is flagged, never killed.
/// </summary>
public sealed class ScriptGuard : IDisposable
{
    /// <summary>Scripts shorter than this carry no analysable payload.</summary>
    private const int MinContentChars = 8;
    /// <summary>Bound on how much of one script we normalise and match.</summary>
    private const int MaxAnalysisChars = 65_536;
    private const int MaxQueue = 64;
    private const int ExcerptChars = 240;

    public sealed class Rule
    {
        public readonly string Id;
        public readonly string Technique;
        public readonly string Severity;
        public readonly int Weight;
        /// <summary>Every fragment must be present.</summary>
        public readonly string[] All;
        /// <summary>If non-empty, at least one fragment must also be present.</summary>
        public readonly string[] Any;

        public Rule(string id, string technique, string severity, int weight, string[] all, string[]? any = null)
        {
            Id = id; Technique = technique; Severity = severity; Weight = weight;
            All = all; Any = any ?? Array.Empty<string>();
        }
    }

    // All fragments are matched against lower-cased, whitespace-collapsed text, so they must be
    // written lower-case with single spaces.
    private static readonly Rule[] Rules =
    {
        // ── Credential access (T1003) ───────────────────────────────────────────────
        new("SCR-MIMIKATZ", "T1003.001", "high", 60, new[] { "invoke-mimikatz" }),
        new("SCR-SEKURLSA", "T1003.001", "high", 60, new[] { "sekurlsa::" }),
        new("SCR-LSASS-COMSVCS", "T1003.001", "high", 60, new[] { "comsvcs", "minidump" }),
        new("SCR-LSASS-DUMP", "T1003.001", "high", 55, new[] { "lsass" }, new[] { "out-minidump", "dump", "procdump" }),
        new("SCR-SAM-SAVE", "T1003.002", "high", 55, new[] { "reg", "save", "hklm\\sam" }),
        new("SCR-SAM-EXPORT", "T1003.002", "high", 55, new[] { "reg", "export", "hklm\\sam" }),
        new("SCR-SYSTEM-SAVE", "T1003.002", "high", 50, new[] { "reg", "save", "hklm\\system" }),
        new("SCR-SECURITY-SAVE", "T1003.002", "high", 50, new[] { "reg", "save", "hklm\\security" }),
        new("SCR-NTDS-DIT", "T1003.003", "high", 55, new[] { "ntds.dit" }),
        new("SCR-DPAPI-MASTERKEY", "T1003.004", "high", 50, new[] { "masterkey" }, new[] { "dpapi", "vaultcli", "cryptunprotect" }),

        // ── Attack frameworks / offensive tooling ───────────────────────────────────
        new("SCR-REDTEAM-TOOLKIT", "T1059.001", "high", 60, new[] { "sharpsploit" }),
        new("SCR-BLOODHOUND", "T1087.002", "high", 55, new[] { "invoke-bloodhound" }),
        new("SCR-SHARPHOUND", "T1087.002", "high", 55, new[] { "sharphound" }),
        new("SCR-INVOKE-SHELLCODE", "T1055", "high", 60, new[] { "invoke-shellcode" }),
        new("SCR-REFLECTIVE-PE", "T1055.001", "high", 55, new[] { "invoke-reflectivepeinjection" }),
        new("SCR-KEYLOGGER", "T1056.001", "medium", 35, new[] { "getasynckeystate", "setwindowshookex" }),

        // ── Defense evasion (T1562) ─────────────────────────────────────────────────
        new("SCR-AMSI-BYPASS", "T1562.001", "high", 60, new[] { "amsiutils" }),
        new("SCR-AMSI-INITFAIL", "T1562.001", "high", 60, new[] { "amsiinitfailed" }),
        new("SCR-AMSI-SCANBUFFER", "T1562.001", "high", 60, new[] { "amsiscanbuffer" }),
        new("SCR-DEFENDER-OFF", "T1562.001", "high", 55, new[] { "set-mppreference" },
            new[] { "disablerealtimemonitoring", "disablebehaviormonitoring", "disableioavprotection", "disablescriptscanning" }),
        new("SCR-DEFENDER-EXCL", "T1562.001", "medium", 30, new[] { "add-mppreference", "exclusionpath" }),
        new("SCR-FIREWALL-OFF", "T1562.004", "medium", 30, new[] { "advfirewall", "state off" }),
        new("SCR-SHADOW-COPY-DELETE", "T1490", "high", 55, new[] { "vssadmin", "delete", "shadows" }),
        new("SCR-BCDEDIT", "T1490", "medium", 30, new[] { "bcdedit" }, new[] { "/set", "delete" }),

        // ── Execution / delivery (T1059, T1105) ─────────────────────────────────────
        new("SCR-DOWNLOAD-IEX", "T1105", "high", 50,
            new[] { "invoke-expression" },
            new[] { "downloadstring", "downloadfile", "invoke-webrequest", "invoke-restmethod", "net.webclient" }),
        new("SCR-IEX-DL", "T1105", "high", 50, new[] { "iex" },
            new[] { "downloadstring", "downloadfile", "invoke-webrequest", "net.webclient" }),
        new("SCR-B64-IEX", "T1059.001", "high", 50, new[] { "frombase64string" },
            new[] { "invoke-expression", "iex", "createinstance" }),
        new("SCR-ENCODEDCMD", "T1059.001", "high", 45, new[] { "encodedcommand" }),
        new("SCR-WMIC-EXEC", "T1047", "high", 45, new[] { "wmic", "process call create" }),
        new("SCR-SCHTASKS-PS", "T1053.005", "high", 45, new[] { "schtasks", "/create" },
            new[] { "powershell", "-enc", "-w hidden", "windowstyle hidden" }),
        new("SCR-BITS-TRANSFER", "T1197", "medium", 30, new[] { "bitsadmin", "/transfer" }),
        new("SCR-CERTUTIL-FETCH", "T1140", "medium", 30, new[] { "certutil" }, new[] { "-urlcache", "-decode", "-encode" }),
        new("SCR-MSHTA-EXEC", "T1218.005", "medium", 30, new[] { "mshta" }, new[] { "http", "javascript", "vbscript" }),

        // ── C2 / lateral movement ───────────────────────────────────────────────────
        new("SCR-REVERSE-SHELL", "T1571", "high", 50, new[] { "system.net.sockets.tcpclient" },
            new[] { "getstream", "beginconnect", "invoke-expression" }),
        new("SCR-PSREMOTE-CRED", "T1021.006", "medium", 30, new[] { "invoke-command", "-computername", "-credential" }),
        new("SCR-RDP-ENABLE", "T1021.001", "medium", 30, new[] { "fdenytsconnections", "0" }),
        new("SCR-NET-USER-ADD", "T1136.001", "medium", 25, new[] { "net user", "/add" }),
        new("SCR-NET-ADMINS", "T1098", "medium", 25, new[] { "net localgroup", "administrators" }),
        new("SCR-RUNAS-ESCALATE", "T1134", "medium", 25, new[] { "start-process", "-verb runas" }),
    };

    private readonly Storyteller _storyteller;
    private readonly ConcurrentQueue<Pending> _queue = new();
    private readonly Thread _worker;
    private readonly CancellationTokenSource _cts = new();
    private readonly object _reportedLock = new();
    private readonly Dictionary<uint, (string rule, int hash)> _reported = new();
    // PowerShell re-submits the same profile/function text constantly, and rescanning identical
    // content in the SAME process is pure waste. Carrying the pid in the key is what keeps that
    // saving honest: a script that ran harmlessly in one process must still be scanned when a
    // different process runs the same bytes, otherwise one benign execution would permanently
    // blind the detector to a re-used attack payload.
    private readonly HashSet<(uint Pid, int Hash)> _seenContent = new();
    private int _disposed;

    public int TotalScanned;
    public int TotalHits;
    public int TotalBlocked;
    public int DroppedBacklog;

    private readonly struct Pending
    {
        public readonly uint Pid;
        public readonly string Source;
        public readonly string Content;
        public Pending(uint pid, string source, string content) { Pid = pid; Source = source; Content = content; }
    }

    public ScriptGuard(Storyteller storyteller)
    {
        _storyteller = storyteller;
        _worker = new Thread(Loop) { IsBackground = true, Name = "Nexus-ScriptGuard", Priority = ThreadPriority.BelowNormal };
    }

    public void Start() => _worker.Start();

    /// <summary>Called from the ETW dispatch thread. Enqueue only — never blocks, never analyses.</summary>
    public void Submit(uint pid, string source, string content)
    {
        if (Volatile.Read(ref _disposed) == 1) return;
        if (pid == 0 || string.IsNullOrEmpty(content) || content.Length < MinContentChars) return;
        if (Volatile.Read(ref EngineState.BypassMode) != 0) return;

        // Bounded: a PowerShell loop that submits thousands of blocks must not grow this without
        // limit. Dropping backlog is reported in the 60 s STATS line rather than silently.
        if (_queue.Count >= MaxQueue)
        {
            Interlocked.Increment(ref DroppedBacklog);
            return;
        }
        _queue.Enqueue(new Pending(pid, source, content));
    }

    private void Loop()
    {
        while (Volatile.Read(ref EngineState.ShuttingDown) == 0 && !_cts.IsCancellationRequested)
        {
            try
            {
                if (_queue.TryDequeue(out Pending p))
                    Process(p);
                else
                    _cts.Token.WaitHandle.WaitOne(50);
            }
            catch (OperationCanceledException) { break; }
            catch (Exception ex)
            {
                Console.WriteLine($"[SCRIPTGUARD] worker fault (non-fatal): {ex.Message}");
            }
        }
    }

    private void Process(in Pending p)
    {
        string content = Normalize(p.Content);
        if (content.Length < MinContentChars) return;

        int contentHash = content.GetHashCode();
        lock (_seenContent)
        {
            if (!_seenContent.Add((p.Pid, contentHash))) return;
            if (_seenContent.Count > 4096) _seenContent.Clear();
        }

        Interlocked.Increment(ref TotalScanned);

        Rule? hit = Match(content);
        if (hit == null) return;

        int key = contentHash ^ hit.Id.GetHashCode();
        lock (_reportedLock)
        {
            if (_reported.TryGetValue(p.Pid, out var prev) && prev.rule == hit.Id && prev.hash == key) return;
            if (_reported.Count > 4096) _reported.Clear();
            _reported[p.Pid] = (hit.Id, key);
        }
        Interlocked.Increment(ref TotalHits);

        string image = ResolveImage(p.Pid);
        string excerpt = Excerpt(content, hit);

        var (score, allowlisted, _, _) = _storyteller.ReportCommandThreat(p.Pid, 0, image, hit.Id, hit.Weight);
        if (allowlisted)
        {
            EventBus.Guard(p.Pid, 0, image, excerpt, hit.Id, hit.Technique, hit.Severity, "allowlisted", string.Empty, score);
            Console.WriteLine($"[SCRIPTGUARD] allowlisted pid={p.Pid} img={image} rule={hit.Id} :: {excerpt}");
            return;
        }

        // Same gate as the command-line guardian: high severity, or the cumulative score crossed
        // the reactive-kill threshold. A lone medium hit is flagged, never killed.
        bool terminated = false;
        if (string.Equals(hit.Severity, "high", StringComparison.OrdinalIgnoreCase) ||
            score >= SafeProcessKiller.KillScoreThreshold)
        {
            terminated = SafeProcessKiller.Terminate(p.Pid,
                $"script rule {hit.Id} ({hit.Technique}) sev={hit.Severity} via {p.Source}", score);
        }

        string action = terminated ? "terminated" : "flagged";
        if (terminated) Interlocked.Increment(ref TotalBlocked);
        EventBus.Guard(p.Pid, 0, image, excerpt, hit.Id, hit.Technique, hit.Severity, action, string.Empty, score);
        Console.WriteLine($"[SCRIPTGUARD] {action} pid={p.Pid} img={image} rule={hit.Id} ({hit.Technique}) sev={hit.Severity} score={score} src={p.Source} :: {excerpt}");
    }

    private static Rule? Match(string content)
    {
        foreach (Rule r in Rules)
        {
            bool ok = true;
            foreach (string f in r.All)
                if (content.IndexOf(f, StringComparison.Ordinal) < 0) { ok = false; break; }
            if (!ok) continue;
            if (r.Any.Length > 0)
            {
                ok = false;
                foreach (string f in r.Any)
                    if (content.IndexOf(f, StringComparison.Ordinal) >= 0) { ok = true; break; }
            }
            if (ok) return r;
        }
        return null;
    }

    /// <summary>Lower-case and collapse whitespace so a payload split across lines still matches.</summary>
    private static string Normalize(string raw)
    {
        int len = Math.Min(raw.Length, MaxAnalysisChars);
        var sb = new System.Text.StringBuilder(len);
        bool pendingSpace = false;
        for (int i = 0; i < len; i++)
        {
            char c = raw[i];
            if (c == '\r' || c == '\n' || c == '\t' || c == ' ')
            {
                pendingSpace = sb.Length > 0;
                continue;
            }
            if (pendingSpace) { sb.Append(' '); pendingSpace = false; }
            sb.Append(c >= 'A' && c <= 'Z' ? (char)(c + 32) : c);
        }
        return sb.ToString();
    }

    private static string Excerpt(string content, Rule rule)
    {
        int at = content.IndexOf(rule.All[0], StringComparison.Ordinal);
        if (at < 0) at = 0;
        int start = Math.Max(0, at - 60);
        int take = Math.Min(ExcerptChars, content.Length - start);
        string s = content.Substring(start, take);
        return (start > 0 ? "…" : string.Empty) + s + (start + take < content.Length ? "…" : string.Empty);
    }

    private static string ResolveImage(uint pid)
    {
        if (ProcessSnapshotCache.TryGetName(pid, out var name) && name.Length > 0) return name;
        return "unknown";
    }

    public void Dispose()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0) return;
        try { _cts.Cancel(); _worker.Join(500); } catch { }
    }
}
