using System;
using System.Collections.Generic;
using System.Diagnostics;

namespace NexusAV.Engine;

/// <summary>
/// One shared, throttled snapshot of the live process list for ALL user-mode monitors.
///
/// Before this existed, ~8 monitor threads each took their own full Toolhelp32/GetProcesses
/// snapshot on independent timers (25 Hz guardian poll + one snapshot PER evaluated process,
/// 20 Hz shield loop, 2 Hz injection/hardware loops, ...). Each snapshot walks every process
/// and thread while holding kernel locks, so dozens of snapshots per second stalled the whole
/// machine the moment the engine started — the GUI "freeze" the user reported.
///
/// Now every monitor reads this cache. A fresh snapshot is taken at most once per
/// <see cref="RefreshIntervalMs"/> (single worker under lock, overlapping requests reuse the
/// last list), the result is an immutable list that is swapped atomically, and every
/// Process handle is disposed on the spot. Monitors polling slower than the refresh interval
/// pay zero snapshot cost.
/// </summary>
public static class ProcessSnapshotCache
{
    public const int RefreshIntervalMs = 1000;

    public sealed record ProcSnapshotEntry(uint Pid, string Name);

    private static readonly object _refreshLock = new();
    private static volatile IReadOnlyList<ProcSnapshotEntry> _snapshot = Array.Empty<ProcSnapshotEntry>();
    private static long _lastRefresh;

    public static IReadOnlyList<ProcSnapshotEntry> Snapshot
    {
        get
        {
            long now = Environment.TickCount64;
            if (now - Volatile.Read(ref _lastRefresh) < RefreshIntervalMs)
                return _snapshot;
            lock (_refreshLock)
            {
                now = Environment.TickCount64;
                if (now - _lastRefresh < RefreshIntervalMs)
                    return _snapshot;
                Process[] procs;
                try { procs = Process.GetProcesses(); }
                catch { return _snapshot; }
                var list = new List<ProcSnapshotEntry>(procs.Length);
                foreach (var p in procs)
                {
                    try { list.Add(new ProcSnapshotEntry((uint)p.Id, p.ProcessName)); }
                    catch { }
                    finally { p.Dispose(); }
                }
                _snapshot = list;
                _lastRefresh = now;
                return list;
            }
        }
    }

    public static bool TryGetName(uint pid, out string name)
    {
        var snap = Snapshot;
        for (int i = 0; i < snap.Count; i++)
        {
            if (snap[i].Pid == pid) { name = snap[i].Name; return true; }
        }
        name = string.Empty;
        return false;
    }
}
