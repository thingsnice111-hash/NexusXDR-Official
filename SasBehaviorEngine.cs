using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;

namespace NexusAV.Engine;

/// <summary>
/// SAS — Signature-free Anomaly Signatures. Instead of static file signatures, SAS maps
/// each process's real activity into a 3D behavioral trajectory:
///   X (spatial)  = memory-runtime anomaly: private RWX/JIT allocations, injection edges
///   Y (temporal) = IO intensity: write/read throughput deltas vs a per-process EMA baseline
///   Z (spread)   = fan-out: handle growth, recent spawn/child activity
///
/// All inputs are measured from the live kernel counters (GetProcessIoCounters,
/// GetProcessTimes, GetProcessHandleCount, K32GetProcessMemoryInfo) plus the engine's own
/// ETW/graph feeds — no signatures, no file uploads, no synthesis. A sustained,
/// baseline-relative write burst with a high write-operation rate is flagged as an
/// "encrypting" trajectory even for never-seen binaries. Detection-only: scores feed the
/// Storyteller ledger; the DCA gate and existing act thresholds still decide any response.
/// </summary>
public sealed class SasBehaviorEngine : IDisposable
{
    private const int SampleIntervalMs = 2000;
    private const int MaxSampledPerPass = 128;
    private const double EmaAlpha = 0.35;
    private const double SustainedWriteFloorBps = 1024 * 1024;  // sustained write floor for "encrypting"
    private const double SustainedOpsFloor = 10;                // write operations/sec floor
    private const int SustainedSamplesNeeded = 3;

    private sealed class Traj
    {
        public ulong CreationTime;
        public ulong LastReadBytes, LastWriteBytes;
        public ulong LastWriteOps;
        public ulong LastCpu100ns;
        public long LastSampleMs;
        public double EmaWriteBps;
        public double EmaCpuPct;
        public int Samples;
        public int SustainedStreak;
        public string Shape = "stable";
        public double X, Y, Z;
        public int Score;
        public long LastPublishMs;
        public int LastPublishedScore = -1;
        public string LastPublishedShape = "";
        public long LastSasCreditMs;
        public readonly Queue<double> WriteHistory = new();
    }

    private readonly Storyteller _story;
    private readonly StorytellerStable _feed;
    private readonly ConcurrentDictionary<uint, Traj> _trajectories = new();
    private readonly Thread _thread;
    private readonly CancellationTokenSource _cts = new();
    private int _disposed;
    private long _lastPurgeMs;

    public int ScoredProcesses => _trajectories.Count;
    public int EncryptingFlags;
    public int ErraticFlags;

    public SasBehaviorEngine(Storyteller story, StorytellerStable feed)
    {
        _story = story;
        _feed = feed;
        _thread = new Thread(Loop) { IsBackground = true, Name = "Nexus-SAS", Priority = ThreadPriority.BelowNormal };
    }

    public void Start() => _thread.Start();

    private void Loop()
    {
        // Stagger the first pass so engine start-up (ETW flood, boot scans) is not taxed.
        try { TaskDelay(6000); } catch { }
        while (Volatile.Read(ref EngineState.ShuttingDown) == 0 && !_cts.IsCancellationRequested)
        {
            try
            {
                if (Volatile.Read(ref EngineState.BypassMode) == 0) SamplePass();
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[SAS] sample pass fault (non-fatal): {ex.Message}");
            }
            try { TaskDelay(SampleIntervalMs); } catch { }
        }
    }

    private void TaskDelay(int ms) => _cts.Token.WaitHandle.WaitOne(ms);

    private void SamplePass()
    {
        long now = Environment.TickCount64;

        // Selection: (1) every scored/flagged storyteller node, (2) previous hot writers,
        // round-robin through the live snapshot up to the cap. Bounded handle opens per pass.
        var pick = new List<uint>(MaxSampledPerPass);
        var seen = new HashSet<uint>();

        foreach (var node in _story.Processes.Values)
        {
            if (pick.Count >= MaxSampledPerPass) break;
            if (node.Pid <= 4) continue;
            if (node.Confidence <= 0 && node.InAllowlist) continue;
            if (seen.Add(node.Pid)) pick.Add(node.Pid);
        }

        foreach (var kv in _trajectories)
        {
            if (pick.Count >= MaxSampledPerPass) break;
            if (seen.Add(kv.Key)) pick.Add(kv.Key);
        }

        var snap = ProcessSnapshotCache.Snapshot;
        int start = (int)(now / SampleIntervalMs % Math.Max(1, snap.Count));
        for (int i = 0; i < snap.Count && pick.Count < MaxSampledPerPass; i++)
        {
            var e = snap[(start + i) % snap.Count];
            if (e.Pid <= 4 || e.Pid == 4) continue;
            if (seen.Add(e.Pid)) pick.Add(e.Pid);
        }

        foreach (uint pid in pick) SampleOne(pid, now);

        if (now - _lastPurgeMs > 120000)
        {
            _lastPurgeMs = now;
            PurgeStale(now);
        }
    }

    private void SampleOne(uint pid, long now)
    {
        IntPtr h = OpenProcess(ProcessQueryLimitedInformation, false, pid);
        if (h == IntPtr.Zero) { _trajectories.TryRemove(pid, out _); return; }
        try
        {
            if (!GetProcessTimes(h, out long creation, out _, out long kernel, out long user)) return;
            if (!GetProcessIoCounters(h, out IoCounters io)) return;
            GetProcessHandleCount(h, out uint handles);
            ulong privateBytes = 0;
            if (K32GetProcessMemoryInfo(h, out ProcessMemoryCounters pmc, (uint)Marshal.SizeOf<ProcessMemoryCounters>()))
                privateBytes = pmc.PagefileUsage;

            ulong cpu100ns = (ulong)(kernel + user);
            var t = _trajectories.GetOrAdd(pid, _ => new Traj());

            // PID-reuse guard: a different creation time means a different process.
            ulong creationBits = unchecked((ulong)creation);
            if (t.CreationTime != 0 && t.CreationTime != creationBits)
            {
                _trajectories[pid] = new Traj { CreationTime = creationBits };
                return; // first sample for the new process
            }
            if (t.CreationTime == 0)
            {
                t.CreationTime = creationBits;
                t.LastSampleMs = now;
                t.LastReadBytes = io.ReadTransferCount;
                t.LastWriteBytes = io.WriteTransferCount;
                t.LastWriteOps = io.WriteOperationCount;
                t.LastCpu100ns = cpu100ns;
                return;
            }

            long dtMs = now - t.LastSampleMs;
            if (dtMs < 500) return;

            ulong dWrite = io.WriteTransferCount >= t.LastWriteBytes ? io.WriteTransferCount - t.LastWriteBytes : 0;
            ulong dRead = io.ReadTransferCount >= t.LastReadBytes ? io.ReadTransferCount - t.LastReadBytes : 0;
            ulong dWriteOps = io.WriteOperationCount >= t.LastWriteOps ? io.WriteOperationCount - t.LastWriteOps : 0;
            ulong dCpu = cpu100ns >= t.LastCpu100ns ? cpu100ns - t.LastCpu100ns : 0;

            double writeBps = dWrite * 1000.0 / dtMs;
            double readBps = dRead * 1000.0 / dtMs;
            double writeOpsPerSec = dWriteOps * 1000.0 / dtMs;
            double cpuPct = dCpu / (dtMs * 10000.0) * 100.0; // % of one core

            double baselineWrite = t.EmaWriteBps;
            double baselineHint = Math.Max(t.EmaWriteBps, SustainedWriteFloorBps);
            bool keepBaseline = t.SustainedStreak > 0 || writeBps > baselineHint * 2.0;
            if (!keepBaseline)
            {
                // Baseline adapts only while the process is quiet; during a burst it is
                // frozen so a sustained attack cannot EMA-average itself into looking normal.
                t.EmaWriteBps = t.Samples == 0 ? writeBps : EmaAlpha * writeBps + (1 - EmaAlpha) * t.EmaWriteBps;
            }
            t.EmaCpuPct = t.Samples == 0 ? cpuPct : EmaAlpha * cpuPct + (1 - EmaAlpha) * t.EmaCpuPct;
            t.LastReadBytes = io.ReadTransferCount;
            t.LastWriteBytes = io.WriteTransferCount;
            t.LastWriteOps = io.WriteOperationCount;
            t.LastCpu100ns = cpu100ns;
            t.LastSampleMs = now;
            t.Samples++;

            t.WriteHistory.Enqueue(writeBps);
            while (t.WriteHistory.Count > 30) t.WriteHistory.Dequeue();

            // ── Trajectory axes (all real measurements) ─────────────────────
            int rwx = 0, injectEdges = 0;
            bool allowlisted = false;
            if (_story.Processes.TryGetValue(pid, out var node))
            {
                rwx = node.JitAllocations.Count;
                allowlisted = node.InAllowlist;
            }
            foreach (var e in _story.Graph.GetEdges(pid))
                if (e.Type is EdgeType.ThreadInject or EdgeType.RwxInject) injectEdges++;

            double x = Math.Min(100, rwx * 10 + injectEdges * 20 + (allowlisted ? 0 : 5));
            double y = Math.Min(100, Math.Log2(1 + writeBps / 65536.0) * 15);
            double z = Math.Min(100, handles / 50.0 + injectEdges * 10);

            // Encrypting-shape test: sustained write burst above the absolute floor AND
            // either above this process's established baseline or a 3x jump over it. The
            // absolute floor keeps write-only log streams out; the relative test catches
            // an attack ramping above an already-active process.
            bool aboveBaseline = writeBps > SustainedWriteFloorBps &&
                (baselineWrite < SustainedWriteFloorBps || writeBps > baselineWrite * 3.0);
            bool opHeavy = writeOpsPerSec >= SustainedOpsFloor;
            if (aboveBaseline && opHeavy) t.SustainedStreak++;
            else t.SustainedStreak = 0;

            double mean = 0, variance = 0;
            if (t.WriteHistory.Count >= 6)
            {
                foreach (double v in t.WriteHistory) mean += v;
                mean /= t.WriteHistory.Count;
                foreach (double v in t.WriteHistory) variance += (v - mean) * (v - mean);
                variance /= t.WriteHistory.Count;
            }
            double cv = mean > 0 ? Math.Sqrt(variance) / mean : 0;

            string shape;
            if (t.SustainedStreak >= SustainedSamplesNeeded) shape = "encrypting";
            else if (aboveBaseline) shape = "burst";
            else if (cv > 1.5 && mean > 128 * 1024) shape = "erratic";
            else shape = "stable";

            int score = ComputeScore(writeBps, writeOpsPerSec, cpuPct, x, z, shape);

            t.Shape = shape;
            t.X = x; t.Y = y; t.Z = z;
            t.Score = score;

            // ── Report to the ledger + story (real correlation only) ────────
            if (shape == "encrypting" && t.SustainedStreak >= SustainedSamplesNeeded && t.Samples >= 10)
            {
                if (!allowlisted && now - t.LastSasCreditMs > 300000)
                {
                    // Pull this image's real Authenticode state before crediting: an app that
                    // was already writing hard when the engine started (log/session writers)
                    // has no warm-up baseline, and a trusted signature is real counter-evidence.
                    _story.VerifyAndAttachSignature(pid);
                    if (_story.Processes.TryGetValue(pid, out var vnode) && vnode.InAllowlist)
                    {
                        allowlisted = true;
                    }
                    else if (_story.ReportSasTrajectory(pid, "encrypting", score))
                    {
                        t.LastSasCreditMs = now;
                        Interlocked.Increment(ref EncryptingFlags);
                        string why2 = Why(shape, writeBps, baselineWrite, writeOpsPerSec, cpuPct, handles, rwx, injectEdges);
                        EventBus.Detection("sas", score >= 80 ? "shield" : "audit",
                            "Sustained encryption-like write trajectory", $"{ImageName(pid)} (pid {pid}): {why2}", pid);
                    }
                }
            }
            else if (shape == "erratic" && !allowlisted)
            {
                if (now - t.LastSasCreditMs > 600000 && _story.ReportSasTrajectory(pid, "erratic", score))
                {
                    t.LastSasCreditMs = now;
                    Interlocked.Increment(ref ErraticFlags);
                    string why = Why(shape, writeBps, baselineWrite, writeOpsPerSec, cpuPct, handles, rwx, injectEdges);
                    EventBus.Detection("sas", "audit", "Erratic write trajectory",
                        $"{ImageName(pid)} (pid {pid}): {why}", pid);
                }
            }

            // ── Dashboard publish (throttled per process) ───────────────────
            bool shapeChanged = t.LastPublishedShape != shape;
            bool scoreMoved = Math.Abs(score - t.LastPublishedScore) >= 8;
            if ((shapeChanged || scoreMoved || now - t.LastPublishMs >= 15000) &&
                (score >= 25 || shape != "stable"))
            {
                t.LastPublishMs = now;
                t.LastPublishedScore = score;
                t.LastPublishedShape = shape;
                PublishSas(pid, score, shape, x, y, z, writeBps, readBps, writeOpsPerSec, cpuPct, handles, privateBytes, allowlisted);
            }
        }
        catch { _trajectories.TryRemove(pid, out _); }
        finally { CloseHandle(h); }
    }

    private static int ComputeScore(double writeBps, double opsPerSec, double cpuPct, double x, double z, string shape)
    {
        double writeScore = Math.Min(55, Math.Log2(1 + writeBps / 32768.0) * 9);
        double opsScore = Math.Min(20, opsPerSec);
        double cpuScore = Math.Min(10, cpuPct / 10.0);
        double spatial = Math.Min(10, x / 10.0);
        double spread = Math.Min(5, z / 20.0);
        double total = writeScore + opsScore + cpuScore + spatial + spread;
        if (shape == "encrypting") total = Math.Max(total, 85);
        else if (shape == "burst") total = Math.Min(total, 70);
        return (int)Math.Clamp(total, 0, 100);
    }

    private static string Why(string shape, double writeBps, double baseline, double ops, double cpuPct, uint handles, int rwx, int inject)
    {
        var sb = new StringBuilder(160);
        sb.Append(shape == "encrypting" ? "sustained write burst" : "write variance")
          .Append(": write ").Append(Kb(writeBps)).Append("/s (baseline ").Append(Kb(baseline)).Append("/s)")
          .Append(", ").Append(ops.ToString("F0", CultureInfo.InvariantCulture)).Append(" write-ops/s")
          .Append(", cpu ").Append(cpuPct.ToString("F0", CultureInfo.InvariantCulture)).Append('%')
          .Append(", handles ").Append(handles);
        if (rwx > 0) sb.Append(", rwx-regions ").Append(rwx);
        if (inject > 0) sb.Append(", injection-edges ").Append(inject);
        return sb.ToString();
    }

    private static string Kb(double bps)
    {
        if (bps >= 1024 * 1024) return (bps / (1024 * 1024)).ToString("F1", CultureInfo.InvariantCulture) + " MB";
        return (bps / 1024).ToString("F0", CultureInfo.InvariantCulture) + " KB";
    }

    private void PublishSas(uint pid, int score, string shape, double x, double y, double z,
        double writeBps, double readBps, double ops, double cpuPct, uint handles, ulong privateBytes, bool allowlisted)
    {
        string img = ImageName(pid);
        var sb = new StringBuilder(256);
        sb.Append("{\"t\":\"sas\",\"pid\":").Append(pid)
          .Append(",\"img\":").Append(J.Str(img))
          .Append(",\"score\":").Append(score)
          .Append(",\"shape\":").Append(J.Str(shape))
          .Append(",\"allow\":").Append(allowlisted ? "true" : "false")
          .Append(",\"x\":").Append(x.ToString("F1", CultureInfo.InvariantCulture))
          .Append(",\"y\":").Append(y.ToString("F1", CultureInfo.InvariantCulture))
          .Append(",\"z\":").Append(z.ToString("F1", CultureInfo.InvariantCulture))
          .Append(",\"wb\":").Append((long)writeBps)
          .Append(",\"rb\":").Append((long)readBps)
          .Append(",\"ops\":").Append((long)ops)
          .Append(",\"cpu\":").Append(cpuPct.ToString("F1", CultureInfo.InvariantCulture))
          .Append(",\"h\":").Append(handles)
          .Append(",\"mem\":").Append(privateBytes / (1024 * 1024))
          .Append(",\"ts\":").Append(DateTimeOffset.UtcNow.ToUnixTimeMilliseconds())
          .Append('}');
        EventBus.Publish(sb.ToString());
    }

    private string ImageName(uint pid)
    {
        // Live snapshot first: the ledger node may still be the "unknown.exe" placeholder
        // created by a credits/report path that ran before the process was ever identified.
        if (ProcessSnapshotCache.TryGetName(pid, out var name) && name.Length > 0) return name;
        if (_story.Processes.TryGetValue(pid, out var n) && !string.IsNullOrEmpty(n.ImageName)) return n.ImageName;
        return $"pid{pid}";
    }

    private void PurgeStale(long now)
    {
        List<uint>? dead = null;
        foreach (var kv in _trajectories)
        {
            if (now - kv.Value.LastSampleMs > 600000) (dead ??= new List<uint>()).Add(kv.Key);
        }
        if (dead != null)
            foreach (uint pid in dead) _trajectories.TryRemove(pid, out _);
    }

    public void Dispose()
    {
        if (Interlocked.Exchange(ref _disposed, 1) == 0)
        {
            try { _cts.Cancel(); } catch { }
            try { _thread.Join(2000); } catch { }
        }
    }

    // ── Interop ──────────────────────────────────────────────────────────────

    private const uint ProcessQueryLimitedInformation = 0x1000;

    [StructLayout(LayoutKind.Sequential)]
    private struct IoCounters
    {
        public ulong ReadOperationCount;
        public ulong WriteOperationCount;
        public ulong OtherOperationCount;
        public ulong ReadTransferCount;
        public ulong WriteTransferCount;
        public ulong OtherTransferCount;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct ProcessMemoryCounters
    {
        public uint cb;
        public uint PageFaultCount;
        public ulong PeakWorkingSetSize;
        public ulong WorkingSetSize;
        public ulong QuotaPeakPagedPoolUsage;
        public ulong QuotaPagedPoolUsage;
        public ulong QuotaPeakNonPagedPoolUsage;
        public ulong QuotaNonPagedPoolUsage;
        public ulong PagefileUsage;
        public ulong PeakPagefileUsage;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenProcess(uint access, bool inherit, uint pid);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CloseHandle(IntPtr h);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetProcessIoCounters(IntPtr h, out IoCounters counters);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetProcessTimes(IntPtr h, out long creation, out long exit, out long kernel, out long user);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetProcessHandleCount(IntPtr h, out uint count);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool K32GetProcessMemoryInfo(IntPtr h, out ProcessMemoryCounters counters, uint cb);
}
