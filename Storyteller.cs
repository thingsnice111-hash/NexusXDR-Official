using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text;

namespace NexusAV.Engine;

public sealed class ProcessNode
{
    public required uint Pid;
    public required uint ParentPid;
    public required string ImageName;
    public HashSet<uint> JitAllocations = new();
    public int Confidence;
    public bool InAllowlist;
    public bool ChainBonusApplied;
    public SignatureState SigState;
    public byte[]? ImageSha256;
    public DateTimeOffset SigCheckedAt;
    public string? FullImagePath;
    public int SasCredits;
    public int MemCredits;
}

public sealed class Storyteller
{
    private readonly ConcurrentDictionary<uint, ProcessNode> _processes = new();
    private readonly object _addLock = new();
    private readonly HashSet<string> _imageAllowlist = new(StringComparer.OrdinalIgnoreCase)
    {
        "csrss.exe", "lsass.exe", "services.exe", "wininit.exe", "winlogon.exe",
        "svchost.exe", "explorer.exe", "chrome.exe", "msedge.exe", "firefox.exe",
        "cl.exe", "link.exe", "dotnet.exe", "devenv.exe",
        "vgc.exe", "vgtray.exe", "easyanticheat.exe", "beservice.exe"
    };

    public CrossProcessGraph Graph { get; }
    private double _lastDecayTs;

    public IReadOnlyDictionary<uint, ProcessNode> Processes => _processes;

    public static class DcaWeights
    {
        public const int Lbr = 20;
        public const int EtwRwx = 40;
        public const int RemoteThreadInject = 50;
        public const int PpidSpoof = 30;
        public const int UnsignedPe = 15;
        public const int InvalidSig = 25;
        public const int DnsSuspicious = 15;
        public const int ParentHop = 10;
        public const int AllowlistCap = 20;
        public const int PrebootTamper = 80;
        public const int PrebootBootkit = 999;
        public const int SecureBootOff = 60;
        public const int NvramBootTamper = 90;
        public const int TpmLogMissing = 40;
        public const int WifiC2 = 35;
        public const int HiddenProcess = 45;
        public const int SasRansomware = 55;
        public const int SasErratic = 15;
        public const int MemoryIntegrity = 20;
        public const int Mystral = 30;
    }

    public bool PrebootClean { get; private set; } = true;
    public uint PrebootTamperCount { get; private set; } = 0;
    public ulong PrebootIdtBase { get; private set; }
    public ulong PrebootGdtBase { get; private set; }
    public int FirmwareFindings { get; private set; }

    public Storyteller()
    {
        Graph = new CrossProcessGraph();
        _lastDecayTs = 0;
    }

    public ProcessNode GetOrAdd(uint pid, uint parentPid, string imageName)
    {
        if (_processes.TryGetValue(pid, out var existing)) return existing;
        var node = new ProcessNode
        {
            Pid = pid,
            ParentPid = parentPid,
            ImageName = imageName,
            InAllowlist = _imageAllowlist.Contains(imageName)
        };
        try
        {
            using var proc = Process.GetProcessById((int)pid);
            node.FullImagePath = proc.MainModule?.FileName;
        }
        catch
        {
        }
        lock (_addLock)
        {
            if (_processes.TryGetValue(pid, out var winner)) return winner;
            _processes[pid] = node;
        }
        return node;
    }

    public (int score, bool allowlisted, bool audit, bool shouldAct) ReportLbrAnomaly(uint pid)
    {
        var node = GetOrAdd(pid, 0, "unknown.exe");
        node.Confidence += DcaWeights.Lbr;
        ApplyAllowlistDiscount(node);
        return Finalize(node);
    }

    public (int score, bool allowlisted, bool audit, bool shouldAct) ReportEtwTiRwx(uint pid, ulong allocBase)
    {
        var node = GetOrAdd(pid, 0, "unknown.exe");
        bool jitCache = node.JitAllocations.Contains((uint)(allocBase >> 16));
        if (!jitCache) node.Confidence += DcaWeights.EtwRwx;
        if (allocBase != 0) node.JitAllocations.Add((uint)(allocBase >> 16));
        ApplyAllowlistDiscount(node);
        return Finalize(node);
    }

    public (int score, bool allowlisted, bool audit, bool shouldAct) ReportEtwCrossProcessApi(string api, uint callerPid, uint targetPid, ulong address, uint protect)
    {
        bool rwx = (protect & (0x40u | 0x80u)) != 0 || protect == 0;
        if (rwx || api is "VirtualAllocEx" or "NtAllocateVirtualMemory" or "MapViewOfSection" or "NtMapViewOfSection")
        {
            ReportEtwTiRwx(targetPid != 0 ? targetPid : callerPid, address);
        }
        if (callerPid != 0 && targetPid != 0 && callerPid != targetPid)
        {
            if (api is "WriteProcessMemory" or "NtWriteVirtualMemory" or "SetThreadContext" or "NtSetContextThread" or "MapViewOfSection" or "NtMapViewOfSection")
                return ReportRwxCrossInject(callerPid, targetPid);
        }
        var node = GetOrAdd(callerPid != 0 ? callerPid : targetPid, 0, "unknown.exe");
        ApplyAllowlistDiscount(node);
        return Finalize(node);
    }

    public (int score, bool allowlisted, bool audit, bool shouldAct) ReportThreadInjection(uint victimPid, uint remotePid, ulong startIp)
    {
        var node = GetOrAdd(remotePid, 0, "unknown.exe");
        node.Confidence += DcaWeights.RemoteThreadInject;
        Graph.AddEdge(new CrossEdge(remotePid, victimPid, EdgeType.ThreadInject, DcaWeights.RemoteThreadInject, DateTimeOffset.UtcNow));
        ApplyAllowlistDiscount(node);
        return Finalize(node);
    }

    public (int score, bool allowlisted, bool audit, bool shouldAct) ReportParentMismatch(uint pid, uint declared, uint actual)
    {
        Graph.AddEdge(new CrossEdge(actual, pid, EdgeType.PpidSpoof, DcaWeights.PpidSpoof, DateTimeOffset.UtcNow));
        var node = GetOrAdd(pid, actual, "unknown.exe");
        node.Confidence += DcaWeights.PpidSpoof;
        ApplyAllowlistDiscount(node);
        return Finalize(node);
    }

    public (int score, bool allowlisted, bool audit, bool shouldAct) ReportRwxCrossInject(uint caller, uint target)
    {
        Graph.AddEdge(new CrossEdge(caller, target, EdgeType.RwxInject, 0, DateTimeOffset.UtcNow));
        var callerNode = GetOrAdd(caller, 0, "unknown.exe");
        var targetNode = GetOrAdd(target, 0, "unknown.exe");
        callerNode.Confidence += 10;
        targetNode.Confidence += 20;
        ApplyAllowlistDiscount(callerNode);
        ApplyAllowlistDiscount(targetNode);
        return Finalize(callerNode);
    }

    public (int score, bool allowlisted, bool audit, bool shouldAct) ReportDnsQuery(uint pid, string qname)
    {
        Graph.AddEdge(new CrossEdge(pid, 0, EdgeType.DnsQuery, DcaWeights.DnsSuspicious, DateTimeOffset.UtcNow, qname));
        var node = GetOrAdd(pid, 0, "unknown.exe");

        bool suspicious = false;
        string[] labels = qname.Split('.', StringSplitOptions.RemoveEmptyEntries);
        int labelCount = labels.Length;

        if (qname.EndsWith(".onion", StringComparison.OrdinalIgnoreCase))
        {
            suspicious = true;
        }
        else if (labelCount > 6)
        {
            suspicious = true;
        }
        else if (qname.Length > 20)
        {
            foreach (var label in labels)
            {
                double entropy = ShannonEntropy(label);
                if (entropy > 4.0)
                {
                    suspicious = true;
                    break;
                }
            }
        }

        if (suspicious)
        {
            node.Confidence += DcaWeights.DnsSuspicious;
        }

        ApplyAllowlistDiscount(node);
        return Finalize(node);
    }

    private static double ShannonEntropy(string s)
    {
        if (string.IsNullOrEmpty(s)) return 0.0;
        Dictionary<char, int> freq = new();
        foreach (char c in s)
        {
            if (freq.ContainsKey(c)) freq[c]++;
            else freq[c] = 1;
        }
        double len = s.Length;
        double entropy = 0.0;
        foreach (var kv in freq)
        {
            double p = kv.Value / len;
            entropy -= p * Math.Log(p, 2.0);
        }
        return entropy;
    }

    public void VerifyAndAttachSignature(uint pid)
    {
        var node = GetOrAdd(pid, 0, "unknown");
        if (node.FullImagePath is null) return;
        if ((DateTimeOffset.UtcNow - node.SigCheckedAt).TotalHours < 1) return;

        var (st, msSigned) = WinTrust.VerifyFile(node.FullImagePath!);
        node.SigState = st;
        try
        {
            node.ImageSha256 = BcryptSha256.HashFile(node.FullImagePath!);
        }
        catch
        {
        }
        int delta = st switch
        {
            SignatureState.Unsigned => DcaWeights.UnsignedPe,
            SignatureState.Invalid or SignatureState.Untrusted => DcaWeights.InvalidSig,
            _ => 0
        };
        node.Confidence += delta;
        node.SigCheckedAt = DateTimeOffset.UtcNow;
        if (msSigned) node.InAllowlist = true;
    }

    public void DecayAll(double halfLifeSec, double dtSec)
    {
        double k = Math.Exp(-dtSec * Math.Log(2.0) / Math.Max(1e-9, halfLifeSec));
        foreach (var node in _processes.Values)
        {
            double v = node.Confidence;
            v *= k;
            node.Confidence = (int)Math.Round(v, MidpointRounding.AwayFromZero);
            if (node.InAllowlist && node.Confidence > DcaWeights.AllowlistCap)
                node.Confidence = DcaWeights.AllowlistCap;
        }
    }

    public int DecayTick(double halfLifeSec = 60.0)
    {
        double now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        if (_lastDecayTs == 0)
        {
            _lastDecayTs = now;
            return 0;
        }
        double dt = Math.Max(0, now - _lastDecayTs);
        DecayAll(halfLifeSec, dt);
        _lastDecayTs = now;
        return _processes.Count;
    }

    private void ApplyAllowlistDiscount(ProcessNode node)
    {
        if (node.InAllowlist && node.Confidence > DcaWeights.AllowlistCap)
            node.Confidence = DcaWeights.AllowlistCap;
    }

    private static (int score, bool allowlisted, bool audit, bool shouldAct) Finalize(ProcessNode node)
    {
        int c = Math.Clamp(node.Confidence, 0, 999);
        double s = 1.0 / (1.0 + Math.Exp(-(c - 68.0) / 12.0));
        bool act = s >= 0.97 && !node.InAllowlist;
        bool audit = s >= 0.5 && s < 0.97 && !node.InAllowlist;
        return (c, node.InAllowlist, audit, act);
    }

    public int ReportPrebootResult(uint tamperCount, uint fileCount, ulong idtBase, ulong gdtBase, ulong cr0, ulong cr3)
    {
        PrebootTamperCount = tamperCount;
        PrebootIdtBase = idtBase;
        PrebootGdtBase = gdtBase;
        PrebootClean = tamperCount == 0;

        int globalPenalty = 0;
        if (tamperCount > 0)
        {
            globalPenalty = tamperCount >= 2 ? DcaWeights.PrebootBootkit : DcaWeights.PrebootTamper;
            foreach (var node in _processes.Values)
            {
                if (!node.InAllowlist)
                {
                    node.Confidence += globalPenalty / 2;
                }
            }
            Graph.AddEdge(new CrossEdge(0, uint.MaxValue, EdgeType.RwxInject, globalPenalty, DateTimeOffset.UtcNow,
                $"PREBOOT_TAMPER_{tamperCount}_files"));
        }
        return globalPenalty;
    }

    public int ReportFirmwareAttestation(FirmwareAttestationResult att)
    {
        FirmwareFindings = att.Findings;
        int penalty = 0;
        if (att.SecureBootQueried && !att.SecureBootEnabled) penalty += DcaWeights.SecureBootOff;
        if (att.BootPathTamper) penalty += DcaWeights.NvramBootTamper;
        if (att.TpmPresent && !att.TcgLogParsed) penalty += DcaWeights.TpmLogMissing;
        if (penalty > 0)
        {
            foreach (var node in _processes.Values)
            {
                if (!node.InAllowlist) node.Confidence += penalty / 2;
            }
            Graph.AddEdge(new CrossEdge(0, uint.MaxValue, EdgeType.RwxInject, penalty, DateTimeOffset.UtcNow,
                $"FIRMWARE_{att.Summary}"));
        }
        if (att.BootPathTamper) PrebootClean = false;
        return penalty;
    }

    public (int score, bool allowlisted, bool audit, bool shouldAct) ReportHiddenProcess(uint pid, string imageName, string source)
    {
        var node = GetOrAdd(pid, 0, string.IsNullOrEmpty(imageName) ? "hidden" : imageName);
        node.Confidence += DcaWeights.HiddenProcess;
        Graph.AddEdge(new CrossEdge(pid, 0, EdgeType.PpidSpoof, DcaWeights.HiddenProcess, DateTimeOffset.UtcNow, source));
        ApplyAllowlistDiscount(node);
        return Finalize(node);
    }

    /// <summary>
    /// Second-witness evidence from the Mystral sensor (memory-level findings the engine
    /// itself cannot read unelevated). Adds a fixed weight and a source-tagged graph edge;
    /// the caller decides whether the returned score warrants an action.
    /// </summary>
    public (int score, bool allowlisted, bool audit, bool shouldAct) ReportMystralFinding(uint pid, string imageName, string kind)
    {
        var node = GetOrAdd(pid, 0, string.IsNullOrEmpty(imageName) ? "unknown.exe" : imageName);
        node.Confidence += DcaWeights.Mystral;
        Graph.AddEdge(new CrossEdge(pid, 0, EdgeType.RwxInject, DcaWeights.Mystral, DateTimeOffset.UtcNow, $"MYSTRAL_{kind}"));
        ApplyAllowlistDiscount(node);
        return Finalize(node);
    }

    /// <summary>
    /// Scores a real command-line / script-interpreter detection produced by the
    /// Active Guardian. <paramref name="weight"/> is the rule-specific ATT&amp;CK weight.
    /// </summary>
    public (int score, bool allowlisted, bool audit, bool shouldAct) ReportCommandThreat(uint pid, uint parentPid, string imageName, string ruleId, int weight)
    {
        var node = GetOrAdd(pid, parentPid, string.IsNullOrEmpty(imageName) ? "unknown.exe" : imageName);
        node.Confidence += weight;
        if (!node.ChainBonusApplied && HasHighRiskSpawnerAncestor(pid))
        {
            node.ChainBonusApplied = true;
            node.Confidence += DcaWeights.ParentHop;
        }
        Graph.AddEdge(new CrossEdge(node.ParentPid != 0 ? node.ParentPid : parentPid, pid, EdgeType.RwxInject, weight,
            DateTimeOffset.UtcNow, $"CMDRULE_{ruleId}"));
        ApplyAllowlistDiscount(node);
        return Finalize(node);
    }

    /// <summary>
    /// Record a process-start observation from any real feed (ETW process-create or the
    /// ring buffer). Creates the node and one Tree edge parent→child (deduplicated), so
    /// the GUI graph and ancestry queries see the live process tree.
    /// </summary>
    public void ReportProcessStart(uint pid, uint parentPid, string imageName)
    {
        string leaf = imageName ?? string.Empty;
        int slash = leaf.LastIndexOf('\\');
        if (slash >= 0) leaf = leaf.Substring(slash + 1);
        var node = GetOrAdd(pid, parentPid, string.IsNullOrEmpty(leaf) ? "unknown.exe" : leaf);
        if (pid > 4 && parentPid > 4 && parentPid != pid && !Graph.HasTreeEdge(pid))
            Graph.AddEdge(new CrossEdge(parentPid, pid, EdgeType.Tree, 0, DateTimeOffset.UtcNow, node.ImageName));
    }

    /// <summary>Human-readable parent chain (from graph Tree edges) for alerts and verification reasons.</summary>
    public string DescribeAncestry(uint pid)
    {
        var chain = Graph.GetAncestry(pid);
        if (chain.Count == 0) return string.Empty;
        var sb = new StringBuilder(96);
        int shown = 0;
        foreach (uint p in chain)
        {
            if (shown == 4) { sb.Append("<-..."); break; }
            if (shown > 0) sb.Append("<-");
            sb.Append(_processes.TryGetValue(p, out var n) ? n.ImageName : "pid" + p);
            shown++;
        }
        return sb.ToString();
    }

    private static readonly HashSet<string> HighRiskSpawners = new(StringComparer.OrdinalIgnoreCase)
    {
        "winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "msaccess.exe", "mspub.exe", "onenote.exe"
    };

    private bool HasHighRiskSpawnerAncestor(uint pid)
    {
        foreach (uint anc in Graph.GetAncestry(pid))
            if (_processes.TryGetValue(anc, out var n) && HighRiskSpawners.Contains(n.ImageName))
                return true;
        return false;
    }

    /// <summary>Public sigmoid classification used by the event feed and consumers.</summary>
    public static (bool audit, bool act) Classify(int confidence, bool allowlisted)
    {
        int c = Math.Clamp(confidence, 0, 999);
        double s = 1.0 / (1.0 + Math.Exp(-(c - 68.0) / 12.0));
        bool act = s >= 0.97 && !allowlisted;
        bool audit = s >= 0.5 && s < 0.97 && !allowlisted;
        return (audit, act);
    }

    public int ReportWifiC2(int score, int hitCount)
    {
        int add = Math.Min(DcaWeights.WifiC2 + hitCount * 5, 80);
        Graph.AddEdge(new CrossEdge(0, uint.MaxValue, EdgeType.DnsQuery, add, DateTimeOffset.UtcNow,
            $"WIFI_SEEKER_C2_score={score}_hits={hitCount}"));
        return add;
    }

    /// <summary>
    /// SAS trajectory credit. Returns true when a fresh credit was actually applied —
    /// capped at 3 per process so a long-running suspicious writer cannot drain the
    /// ledger into a permanent act state, and allowlist discount still applies.
    /// </summary>
    public bool ReportSasTrajectory(uint pid, string shape, int score)
    {
        var node = GetOrAddNamed(pid);
        if (node.SasCredits >= 3) return false;
        int w = shape == "encrypting" ? DcaWeights.SasRansomware : DcaWeights.SasErratic;
        node.SasCredits++;
        node.Confidence += w;
        Graph.AddEdge(new CrossEdge(pid, 0, EdgeType.ShieldAction, w, DateTimeOffset.UtcNow,
            $"SAS_{shape.ToUpperInvariant()}_score{score}"));
        ApplyAllowlistDiscount(node);
        return true;
    }

    /// <summary>Memory-integrity finding (report-only). Capped at 2 credits per process.</summary>
    public void ReportMemoryIntegrity(uint pid)
    {
        var node = GetOrAddNamed(pid);
        if (node.MemCredits >= 2) return;
        node.MemCredits++;
        node.Confidence += DcaWeights.MemoryIntegrity;
        Graph.AddEdge(new CrossEdge(pid, 0, EdgeType.ShieldAction, DcaWeights.MemoryIntegrity,
            DateTimeOffset.UtcNow, "MEM_VERIFY"));
        ApplyAllowlistDiscount(node);
    }

    /// <summary>
    /// GetOrAdd for ledger nodes created by report paths that may never have seen the
    /// process through an identifying feed (ETW/ring). Heals the "unknown.exe" placeholder
    /// from the live snapshot so stories and alerts show the real image name.
    /// </summary>
    private ProcessNode GetOrAddNamed(uint pid)
    {
        var node = GetOrAdd(pid, 0, "unknown.exe");
        if (string.Equals(node.ImageName, "unknown.exe", StringComparison.OrdinalIgnoreCase) &&
            ProcessSnapshotCache.TryGetName(pid, out string real) && real.Length > 0)
            node.ImageName = real;
        return node;
    }

    public (uint realPpid, bool spoofed) DetectPpidSpoofing(uint pid, uint declaredParent, uint creatorPid)
    {
        uint real = creatorPid != 0 ? creatorPid : declaredParent;
        bool spoofed = declaredParent != real && real != 0;
        if (spoofed)
        {
            var (s, _, _, _) = ReportParentMismatch(pid, declaredParent, real);
            _ = s;
        }
        return (real, spoofed);
    }
}
