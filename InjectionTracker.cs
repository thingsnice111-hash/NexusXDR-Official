using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Threading;

namespace NexusAV.Engine;

/// <summary>
/// Per-process registry of injection attempts REPORTED to it. It detects nothing and blocks
/// nothing, which is why it is no longer called a blocker.
///
/// Real injection detection is ETW-driven through <see cref="EtwSubscriber"/> (real kernel
/// process/thread events); a detector that concludes "attempt" calls <see cref="RecordAttempt"/>
/// and this class keeps the evidence per target pid. The old WMI-polling "detector" that used to
/// live here fabricated attacker pids with <see cref="Random"/>, emitted a "blocked" shield event
/// every 500 ms for any child of cmd/powershell and leaked a Process handle per poll — it was
/// removed, not renamed.
///
/// Wiring status today: no detector calls <see cref="RecordAttempt"/>, so the registry stays
/// empty and the two events never fire. It is kept as the sink for the ETW thread-create path.
/// </summary>
public sealed class InjectionTracker : IDisposable
{
    private readonly ConcurrentDictionary<uint, ProcessInfo> _processInfo = new();
    private readonly Timer _monitorTimer;
    private volatile bool _isRunning;
    private int _disposed;
    private int _injectionsBlocked;
    private int _injectionsDetected;

    public record ProcessInfo(uint Pid, string Name, DateTime StartTime, List<InjectionAttempt> Attempts);

    public record InjectionAttempt(
        uint SourcePid,
        string Method,
        ulong TargetAddress,
        DateTime Timestamp,
        bool WasBlocked
    );

    public event Action<uint, uint, string>? OnInjectionAttempt;
    public event Action<uint, string>? OnInjectionBlocked;

    public InjectionTracker()
    {
        _monitorTimer = new Timer(MonitorProcesses, null, TimeSpan.FromSeconds(5), TimeSpan.FromSeconds(5));
    }

    public void Start()
    {
        _isRunning = true;
        Console.WriteLine("[INJECTION-TRACKER] attempt registry started — records what ETW detectors report, blocks nothing");
    }

    public void Stop()
    {
        _isRunning = false;
        Console.WriteLine("[INJECTION-TRACKER] attempt registry stopped");
    }

    /// <summary>
    /// Refreshes the live-process registry from the shared throttled snapshot and prunes
    /// entries for processes that have exited (the old version never disposed its
    /// Process objects and never pruned, leaking handles and growing without bound).
    /// </summary>
    private void MonitorProcesses(object? state)
    {
        if (!_isRunning) return;

        try
        {
            var snapshot = ProcessSnapshotCache.Snapshot;
            var live = new HashSet<uint>();
            foreach (var entry in snapshot)
            {
                live.Add(entry.Pid);
                if (!_processInfo.ContainsKey(entry.Pid))
                {
                    _processInfo[entry.Pid] = new ProcessInfo(
                        entry.Pid,
                        entry.Name,
                        DateTime.Now,
                        new List<InjectionAttempt>()
                    );
                }
            }
            foreach (var pid in _processInfo.Keys)
            {
                if (!live.Contains(pid)) _processInfo.TryRemove(pid, out _);
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[INJECTION-TRACKER] Process monitor error: {ex.Message}");
        }
    }

    /// <summary>Records a REAL injection attempt observed by an ETW-sourced detector.</summary>
    public void RecordAttempt(uint targetPid, InjectionAttempt attempt)
    {
        if (_processInfo.TryGetValue(targetPid, out var info))
        {
            lock (info.Attempts)
            {
                info.Attempts.Add(attempt);
            }
        }
        Interlocked.Increment(ref _injectionsDetected);
        if (attempt.WasBlocked) Interlocked.Increment(ref _injectionsBlocked);
        OnInjectionAttempt?.Invoke(attempt.SourcePid, targetPid, attempt.Method);
        if (attempt.WasBlocked) OnInjectionBlocked?.Invoke(targetPid, attempt.Method);
    }

    public List<InjectionAttempt> GetInjectionAttempts(uint pid)
    {
        if (!_processInfo.TryGetValue(pid, out var info)) return new List<InjectionAttempt>();
        lock (info.Attempts) return new List<InjectionAttempt>(info.Attempts);
    }

    public (int TotalAttempts, int Blocked) GetStats()
    {
        return (_injectionsDetected, _injectionsBlocked);
    }

    public void Dispose()
    {
        if (Interlocked.Exchange(ref _disposed, 1) == 0)
        {
            _isRunning = false;
            _monitorTimer?.Dispose();
        }
    }
}
