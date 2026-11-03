using System;
using System.Diagnostics;
using System.Runtime.CompilerServices;
using System.Threading;
using Microsoft.Win32.SafeHandles;

namespace NexusAV.Engine;

public static class EngineState
{
    public static int BypassMode = 0;
    public static int ShuttingDown = 0;
    public static readonly DateTimeOffset StartupTime = DateTimeOffset.UtcNow;
    public static volatile int EmergencyLockdown = 0;

    /// <summary>
    /// 0 = terminate attackers, 1 = detect only — report and log, never kill. The engine starts in
    /// detect-only so a mis-scored rule cannot kill the operator's own tools on first contact;
    /// terminate is an explicit choice made from the GUI ("Response mode").
    /// <see cref="SafeProcessKiller"/> also forces detect-only when its kill-rate fuse trips.
    /// </summary>
    public static volatile int DetectOnlyMode = 1;
}

public enum LockdownKind : byte { None = 0, NetworkIsolation = 1, NmiInjection = 2, FullQuarantine = 3 }

public sealed class Watchdog : IDisposable
{
    private readonly SafeFileHandle _driverHandle;
    private readonly Storyteller? _storyteller;
    private readonly NexusKeepAliveMonitor? _kaMonitor;
    private readonly int _checkIntervalMs;
    private readonly int _missedChallengeThreshold;
    private readonly long _challengeStaleTicks;
    private Thread? _thread;
    private int _successiveMisses;
    private int _disposed;
    private long _lastChallengeTickUs;
    private long _lastChallengeValue;
    private int _totalChallenges;
    private int _totalResponses;
    private int _lockdownActive;

    public int TotalChallenges => Volatile.Read(ref _totalChallenges);
    public int TotalResponses => Volatile.Read(ref _totalResponses);
    public LockdownKind LockdownState { get; private set; } = LockdownKind.None;

    public Watchdog(SafeFileHandle driverHandle, Storyteller? storyteller = null, NexusKeepAliveMonitor? kaMonitor = null,
        int checkIntervalMs = 50, int missedThreshold = 8)
    {
        _driverHandle = driverHandle ?? throw new ArgumentNullException(nameof(driverHandle));
        _storyteller = storyteller;
        _kaMonitor = kaMonitor;
        _checkIntervalMs = checkIntervalMs;
        _missedChallengeThreshold = missedThreshold;
        _challengeStaleTicks = Stopwatch.Frequency * missedThreshold * checkIntervalMs / 1000;
    }

    public void Start()
    {
        ObjectDisposedException.ThrowIf(_disposed == 1, this);
        if (_thread != null) return;

        _thread = new Thread(MonitorLoop)
        {
            IsBackground = true,
            Priority = ThreadPriority.Highest,
            Name = "NexusAV-InvertedWatchdog"
        };
        _thread.Start();
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static long GetTimestampUs()
    {
        return (long)((double)Stopwatch.GetTimestamp() * 1_000_000.0 / Stopwatch.Frequency);
    }

    public void ReportChallengeResponded(uint challenge, long timestampUsFromDriver)
    {
        Interlocked.Increment(ref _totalChallenges);
        Interlocked.Increment(ref _totalResponses);
        Volatile.Write(ref _lastChallengeValue, challenge);
        Volatile.Write(ref _lastChallengeTickUs, GetTimestampUs());
        Interlocked.Exchange(ref _successiveMisses, 0);
    }

    private void MonitorLoop()
    {
        long baseline = GetTimestampUs();
        Volatile.Write(ref _lastChallengeTickUs, baseline);

        while (Volatile.Read(ref EngineState.ShuttingDown) == 0 && Volatile.Read(ref _disposed) == 0)
        {
            if (Volatile.Read(ref EngineState.EmergencyLockdown) == 1 &&
                Interlocked.CompareExchange(ref _lockdownActive, 1, 0) == 0)
            {
                TriggerEmergencyLockdown(LockdownKind.FullQuarantine, "external EngineState flag");
                return;
            }

            // Fallback: also send classic heartbeat IOCTL, which resets driver's KA response timer too
            bool hbOk = PingDriverFallback();

            long nowUs = GetTimestampUs();
            long lastSeen = Volatile.Read(ref _lastChallengeTickUs);
            long gapUs = nowUs - lastSeen;
            long thresholdUs = _missedChallengeThreshold * _checkIntervalMs * 1000L;

            if (gapUs > thresholdUs && Volatile.Read(ref _totalChallenges) > 0)
            {
                int cur = Interlocked.Increment(ref _successiveMisses);
                if (cur >= _missedChallengeThreshold &&
                    Interlocked.CompareExchange(ref _lockdownActive, 1, 0) == 0)
                {
                    TriggerEmergencyLockdown(LockdownKind.FullQuarantine,
                        $"driver KA challenge stale for {gapUs / 1000}ms ({cur} misses, hbOk={hbOk})");
                    return;
                }
            }

            Thread.Sleep(_checkIntervalMs);
        }
    }

    private bool PingDriverFallback()
    {
        if (_driverHandle.IsClosed || _driverHandle.IsInvalid) return false;
        try
        {
            return KernelBridge.DeviceIoControlSimple(
                _driverHandle,
                KernelBridge.IOCTL_NEXUS_HEARTBEAT,
                IntPtr.Zero, 0,
                IntPtr.Zero, 0,
                out _,
                IntPtr.Zero);
        }
        catch
        {
            return false;
        }
    }

    internal void TriggerEmergencyLockdown(LockdownKind kind, string reason)
    {
        LockdownState = kind;
        Interlocked.Exchange(ref EngineState.EmergencyLockdown, 1);
        Console.Error.WriteLine($"[FATAL][{DateTimeOffset.UtcNow:O}] ===== INVERTED WATCHDOG LOCKDOWN ({kind}) ===== reason={reason}");
        Console.Error.WriteLine($"[FATAL] challenges={Volatile.Read(ref _totalChallenges)} responses={Volatile.Read(ref _totalResponses)} misses={Volatile.Read(ref _successiveMisses)}");

        try
        {
            if (_kaMonitor != null)
            {
                var st = _kaMonitor.LastState;
                Console.Error.WriteLine($"[FATAL] NexusKeepAlive state = {st}");
            }
            if (_storyteller != null)
            {
                Console.Error.WriteLine($"[FATAL] Preboot clean = {_storyteller.PrebootClean} tamperCount={_storyteller.PrebootTamperCount}");
            }
        }
        catch { }

        // ---- 4-fázová reakce místo pasivního Bypass módu: ----
        try
        {
            if (_driverHandle != null && !_driverHandle.IsClosed && !_driverHandle.IsInvalid)
            {
                // 1) WFP Kill Switch via IOCTL -> blokuje síť mimo systémové PID
                bool wfpOk = KernelBridge.ActivateWfpBlock(_driverHandle);
                Console.Error.WriteLine($"[LOCKDOWN-1/3] WFP Kill Switch: ok={wfpOk}");

                // 2) De-escalate non-critical hooking (minimal bypass only for non-network)
                //    intentionally NOT calling IOCTL_NEXUS_BYPASS to keep OB callbacks + process notify
            }
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"[LOCKDOWN-1/3] WFP exception: {ex.Message}");
        }

        try
        {
            Console.Error.WriteLine("[LOCKDOWN-2/3] Firmware re-attestation (TPM/UEFI) replacing VTL1 NMI path");
            using var tpm = new TpmValidationEngine();
            FirmwareAttestationResult att = tpm.RunAttestation();
            Console.Error.WriteLine($"[LOCKDOWN-3/3] {att.Summary}");
            if (_storyteller != null) _storyteller.ReportFirmwareAttestation(att);
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"[LOCKDOWN-2+3/3] TPM attestation exception: {ex.Message}");
        }

        Console.Error.WriteLine("[FATAL] Emergency lockdown sequence complete. Engine running in QUARANTINE MODE.");
    }

    public bool ActivateEmergencyBypass()
    {
        if (_driverHandle == null || _driverHandle.IsClosed || _driverHandle.IsInvalid) return false;
        try
        {
            Interlocked.Exchange(ref EngineState.BypassMode, 1);
            bool ok = KernelBridge.DeviceIoControlSimple(
                _driverHandle,
                KernelBridge.IOCTL_NEXUS_BYPASS,
                IntPtr.Zero, 0,
                IntPtr.Zero, 0,
                out _,
                IntPtr.Zero);
            Console.Error.WriteLine($"[WATCHDOG] Emergency BYPASS requested (via IOCTL_NEXUS_BYPASS 0x803): ok={ok}");
            return ok;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"[WATCHDOG] Emergency BYPASS failed: {ex.Message}");
            return false;
        }
    }

    public void Dispose()
    {
        if (Interlocked.CompareExchange(ref _disposed, 1, 0) != 0) return;
        Volatile.Write(ref EngineState.ShuttingDown, 1);
        _thread?.Join(Math.Min(_checkIntervalMs * 6, 1000));
    }
}
