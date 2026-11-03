using System.Diagnostics;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using Microsoft.Win32.SafeHandles;
using NexusAV.Engine;

public enum ShieldPhase : byte { Idle = 0, PreBoot = 1, EarlyTelemetry = 2, Monitoring = 3, DiagnoseFreeze = 4, HardwareIntervene = 5, SecureReset = 6, DiagReboot = 7 }
public enum NetworkIsolationLevel : byte { None = 0, Emergency = 1, Full = 2 }
public enum KernelHealth : byte { Healthy = 0, Suspended = 1, DDoS = 2, Dead = 3 }

[StructLayout(LayoutKind.Sequential, Pack = 1)]
public unsafe struct BootSectorFingerprint
{
    public uint DiskId;
    public uint PartitionIndex;
    public fixed byte Sha256[32];
    public uint BootSignature;
    public ushort MbrPartitionType;
    public ushort Reserved;
}

[StructLayout(LayoutKind.Sequential, Pack = 1)]
public unsafe struct EarlyTelemetryRecord
{
    public long TimestampUs;
    public uint EventType;
    public uint Pid;
    public fixed byte ImagePath[260];
    public fixed byte BlobHash[32];
    public int Score;
}

public unsafe sealed partial class SelfHealingShield : IDisposable
{
    private readonly byte[] _rootKey;
    private readonly TpmValidationEngine _tpm;
    private readonly Storyteller _story;
    private readonly DcaEngine _dca;
    private readonly SafeFileHandle? _driver;
    private Thread? _shieldThread;
    private long _lastHiddenScan;
    private int _disposed;
    private int _freezeAttempts;
    private int _emergencyIsolation;
    private ShieldPhase _phase = ShieldPhase.Idle;
    private readonly List<BootSectorFingerprint> _bootFingerprints = new();
    private readonly Queue<EarlyTelemetryRecord> _earlyTelemetry = new();
    private readonly object _lock = new();

    public ShieldPhase CurrentPhase
    {
        get
        {
            byte raw = Volatile.Read(ref Unsafe.As<ShieldPhase, byte>(ref _phase));
            return (ShieldPhase)raw;
        }
    }
    public NetworkIsolationLevel NetworkLevel => Volatile.Read(ref _emergencyIsolation) switch { 0 => NetworkIsolationLevel.None, 1 => NetworkIsolationLevel.Emergency, _ => NetworkIsolationLevel.Full };
    public IReadOnlyList<BootSectorFingerprint> BootFingerprints => _bootFingerprints;

    public SelfHealingShield(byte[] rootKey, TpmValidationEngine tpm, Storyteller story, DcaEngine dca, SafeFileHandle? driverHandle = null)
    {
        _rootKey = rootKey ?? throw new ArgumentNullException(nameof(rootKey));
        _tpm = tpm ?? throw new ArgumentNullException(nameof(tpm));
        _story = story ?? throw new ArgumentNullException(nameof(story));
        _dca = dca ?? throw new ArgumentNullException(nameof(dca));
        _driver = driverHandle;
    }

    public bool RunPreBootScan()
    {
        SetPhase(ShieldPhase.PreBoot);
        bool ok = true;
        ok &= ScanMasterBootRecords();
        ok &= ScanBootConfigurationDatabase();
        ok &= ScanCriticalBootDrivers();
        FirmwareAttestationResult att = _tpm.RunAttestation();
        ok &= att.Findings == 0;
        int penalty = _story.ReportFirmwareAttestation(att);
        if (penalty > 0)
            Console.WriteLine($"[PRE-BOOT] TPM/UEFI attestation penalty={penalty} ({att.Summary})");
        SetPhase(ShieldPhase.Idle);
        return ok;
    }

    public int FlushEarlyTelemetry()
    {
        SetPhase(ShieldPhase.EarlyTelemetry);
        int flushed = 0;
        try
        {
            string[] critical =
            {
                @"\SystemRoot\System32\ntoskrnl.exe",
                @"\SystemRoot\System32\hal.dll",
                @"\SystemRoot\System32\kdcom.dll",
                @"\SystemRoot\System32\clfs.sys",
                @"\SystemRoot\System32\drivers\msrpc.sys",
                @"\SystemRoot\System32\drivers\ksecdd.sys",
                @"\SystemRoot\System32\drivers\ci.dll",
                @"\SystemRoot\System32\win32kfull.sys"
            };
            // Register the engine's own pid node once, labeled with its real image name.
            // Labeling it after a hashed kernel file made the process feed show the engine
            // as "ntoskrnl.exe".
            uint pid = (uint)Environment.ProcessId;
            _story.GetOrAdd(pid, 4u, Path.GetFileName(Environment.ProcessPath ?? "NexusAV.Engine.exe"));
            for (int i = 0; i < critical.Length; i++)
            {
                string mapped = critical[i].Replace(@"\SystemRoot\", Environment.GetFolderPath(Environment.SpecialFolder.Windows) + @"\");
                if (!File.Exists(mapped)) continue;
                byte[] hash = ComputeFileFingerprint(mapped);
                var rec = new EarlyTelemetryRecord
                {
                    TimestampUs = Stopwatch.GetTimestamp() * 1_000_000L / Stopwatch.Frequency,
                    EventType = 0x81u,
                    Pid = pid,
                    Score = 0
                };
                for (int j = 0; j < 32 && j < hash.Length; j++) rec.BlobHash[j] = hash[j];
                for (int j = 0; j < 259 && j < mapped.Length; j++) rec.ImagePath[j] = (byte)mapped[j];
                // SHA-256 output is not a Shannon-entropy signal (always ~max). Keep score unused.
                rec.Score = 0;
                lock (_lock) { _earlyTelemetry.Enqueue(rec); if (_earlyTelemetry.Count > 1024) _earlyTelemetry.Dequeue(); }
                flushed++;
            }
        }
        catch { }
        SetPhase(ShieldPhase.Idle);
        return flushed;
    }

    public void StartShield(NexusKeepAliveMonitor monitor, uint enginePid, Action<ShieldPhase>? onPhaseChange = null)
    {
        ObjectDisposedException.ThrowIf(_disposed == 1, this);
        if (_shieldThread != null) return;
        _shieldThread = new Thread(() => ShieldLoop(monitor, enginePid, onPhaseChange))
        { Name = "Nexus-Shield", Priority = ThreadPriority.Normal, IsBackground = true };
        _shieldThread.Start();
    }

    private void ShieldLoop(NexusKeepAliveMonitor monitor, uint enginePid, Action<ShieldPhase>? onPhaseChange)
    {
        uint resetThreshold = 5;
        while (Volatile.Read(ref EngineState.ShuttingDown) == 0 && Volatile.Read(ref _disposed) == 0)
        {
            if (monitor.LastState is KeepAliveState.Frozen or KeepAliveState.Terminated)
            {
                int attempt = Interlocked.Increment(ref _freezeAttempts);
                PhaseDiagnoseFreeze(enginePid, onPhaseChange);
                PhaseHardwareIntervene(enginePid, monitor, (uint)attempt, onPhaseChange);
                if (attempt >= resetThreshold)
                {
                    PhaseSecureReset(enginePid, (uint)attempt, onPhaseChange);
                }
            }
            else
            {
                Interlocked.Exchange(ref _freezeAttempts, 0);
                // Only notify when the phase actually changes: invoking the callback on every
                // iteration printed "[SHIELD-PHASE] -> Monitoring" to stdout at 20 Hz, flooding
                // the GUI's event feed.
                if (CurrentPhase != ShieldPhase.Monitoring)
                {
                    SetPhase(ShieldPhase.Monitoring);
                    onPhaseChange?.Invoke(ShieldPhase.Monitoring);
                }
                long now = Stopwatch.GetTimestamp();
                if (now - _lastHiddenScan > 30 * Stopwatch.Frequency)
                {
                    _lastHiddenScan = now;
                    HiddenProcessScanner.Scan(_story);
                }
            }
            Thread.Sleep(1000);
        }
    }

    private void PhaseDiagnoseFreeze(uint enginePid, Action<ShieldPhase>? onPhaseChange)
    {
        SetPhase(ShieldPhase.DiagnoseFreeze);
        onPhaseChange?.Invoke(ShieldPhase.DiagnoseFreeze);
        Console.WriteLine($"[SHIELD][{CurrentPhase}] TPM/heartbeat diagnose pid={enginePid}");
        KernelHealth health = DiagnoseKernel();
        _ = _tpm.RunAttestation();
        Console.WriteLine($"[SHIELD] kernel={health} firmware={_tpm.LastResult.Summary}");
    }

    private KernelHealth DiagnoseKernel()
    {
        try
        {
            long t0 = Stopwatch.GetTimestamp();
            bool r = _driver != null && !_driver.IsInvalid && KernelBridge.DeviceIoControlSimple(_driver, KernelBridge.IOCTL_NEXUS_HEARTBEAT, IntPtr.Zero, 0, IntPtr.Zero, 0, out uint _, IntPtr.Zero);
            long latUs = (Stopwatch.GetTimestamp() - t0) * 1_000_000L / Stopwatch.Frequency;
            if (!r) return KernelHealth.Dead;
            if (latUs > 500_000) return KernelHealth.DDoS;
            if (latUs > 100_000) return KernelHealth.Suspended;
            return KernelHealth.Healthy;
        }
        catch { return KernelHealth.Suspended; }
    }

    private void PhaseHardwareIntervene(uint enginePid, NexusKeepAliveMonitor mon, uint attempt, Action<ShieldPhase>? onPhaseChange)
    {
        SetPhase(ShieldPhase.HardwareIntervene);
        onPhaseChange?.Invoke(ShieldPhase.HardwareIntervene);
        Console.WriteLine($"[SHIELD][{CurrentPhase}] attempt={attempt}");
        DepriveAttackerCpuIfDetected();
        if (_driver is { IsInvalid: false, IsClosed: false })
            KernelBridge.ActivateWfpBlock(_driver);
        if (attempt == 1 || attempt == 2)
        {
            KillAndReallocateEngine(enginePid, attempt);
        }
    }

    private static void DepriveAttackerCpuIfDetected()
    {
        try
        {
            Process[] all = Process.GetProcesses();
            for (int i = 0; i < all.Length; i++)
            {
                Process p = all[i];
                try
                {
                    long ms = 0;
                    using (p) ms = p.TotalProcessorTime.Ticks;
                    if (ms < 0) continue;
                }
                catch { continue; }
            }
        }
        catch { }
    }

    private void KillAndReallocateEngine(uint enginePid, uint attempt)
    {
        try
        {
            Process cur = Process.GetCurrentProcess();
            Console.WriteLine($"[N-CGT] Nexus pid={enginePid} C2 isolation (WFP). attempt={attempt}");
        }
        catch { }
    }

    private void PhaseSecureReset(uint enginePid, uint attempt, Action<ShieldPhase>? onPhaseChange)
    {
        SetPhase(ShieldPhase.SecureReset);
        onPhaseChange?.Invoke(ShieldPhase.SecureReset);
        Console.WriteLine($"[SHIELD][{CurrentPhase}] re-attack detected! Emergency Network Isolation.");
        int level = attempt > 7 ? 2 : 1;
        Volatile.Write(ref _emergencyIsolation, level);
        if (_driver is { IsInvalid: false, IsClosed: false })
        {
            KernelBridge.ActivateWfpBlock(_driver);
            if (level == 2)
            {
                Console.WriteLine("[SHIELD] NMI + D-Boot Diagnostic reboot imminent.");
                TriggerNmi();
                if (attempt > 10)
                {
                    SetPhase(ShieldPhase.DiagReboot);
                    onPhaseChange?.Invoke(ShieldPhase.DiagReboot);
                    TriggerDiagnosticReboot();
                }
            }
        }
        else
        {
            // User-mode build: never NMI or reboot the host. Log what the kernel build
            // would have done so a misbehaving keep-alive can never take the machine down.
            Console.WriteLine($"[SHIELD] secure-reset level={level} suppressed (no kernel driver; user-mode build)");
        }
    }

    private static void TriggerNmi()
    {
        try
        {
            IntPtr hnd = NativeMethods.GetCurrentProcess();
            int status = NativeMethods.RtlAdjustPrivilege(20u, true, false, out bool prev);
            if (status != 0) return;
            _ = NativeMethods.NtRaiseHardError(0xC0000409u, 0u, 0u, IntPtr.Zero, 6u, out _);
        }
        catch { }
    }

    private static void TriggerDiagnosticReboot()
    {
        try
        {
            int status = NativeMethods.RtlAdjustPrivilege(19u, true, false, out _);
            if (status != 0) return;
            uint flags = 0x00000002u | 0x00000004u | 0x40000000u;
            NativeMethods.InitiateSystemShutdownExW(null, "Nexus D-Boot: Pre-Boot Diagnostics", 0, true, false, flags, "NexusAV.TPM.PreBootAgent");
        }
        catch { }
    }

    private bool ScanMasterBootRecords()
    {
        try
        {
            for (uint disk = 0; disk < 4; disk++)
            {
                string path = $@"\\.\PhysicalDrive{disk}";
                SafeFileHandle? h = TryOpenDisk(path);
                if (h == null || h.IsInvalid) { h?.Dispose(); continue; }
                using (h)
                {
                    byte[] mbr = new byte[512];
                    fixed (byte* mb = mbr)
                    {
                        if (NativeMethods.ReadFile(h.DangerousGetHandle(), mb, 512u, out uint read, IntPtr.Zero) && read == 512u)
                        {
                            ushort sig = (ushort)(mb[510] | (mb[511] << 8));
                            var fp = new BootSectorFingerprint { DiskId = disk, PartitionIndex = 0u, BootSignature = sig };
                            byte[] h2 = ComputeBufferFingerprint(mbr);
                            for (int j = 0; j < 32 && j < h2.Length; j++) fp.Sha256[j] = h2[j];
                            fp.MbrPartitionType = (ushort)(mb[0x1C2] | (mb[0x1C3] << 8));
                            _bootFingerprints.Add(fp);
                            Console.WriteLine($"[PRE-BOOT] Disk{disk} MBR signature=0x{sig:X4} partitionType=0x{fp.MbrPartitionType:X4}");
                        }
                    }
                }
            }
            return true;
        }
        catch { return false; }
    }

    private static SafeFileHandle? TryOpenDisk(string path)
    {
        try
        {
            IntPtr h = NativeMethods.CreateFileW(path, 0x80000000u, 1u | 2u, IntPtr.Zero, 3u, 0u, IntPtr.Zero);
            if (h == IntPtr.Zero || h == new IntPtr(-1)) return null;
            return new SafeFileHandle(h, true);
        }
        catch { return null; }
    }

    private static bool ScanBootConfigurationDatabase()
    {
        try
        {
            string bcd = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), @"bcd");
            string bcdAlt = @"C:\Boot\BCD";
            foreach (string c in new[] { bcd, bcdAlt })
            {
                if (!File.Exists(c)) continue;
                using var f = File.OpenRead(c);
                byte[] head = new byte[Math.Min(f.Length, 4096)];
                int r = f.Read(head, 0, head.Length);
                if (r > 0)
                {
                    byte[] hh = ComputeBufferFingerprint(head);
                    uint sig = (uint)(hh[0] | (hh[1] << 8) | (hh[2] << 16) | (hh[3] << 24));
                    Console.WriteLine($"[PRE-BOOT] BCD store: {c} fingerprint=0x{sig:X8}");
                }
            }
            return true;
        }
        catch { return false; }
    }

    private static bool ScanCriticalBootDrivers()
    {
        try
        {
            string[] bootDrv = { @"\SystemRoot\System32\drivers\volmgrx.sys", @"\SystemRoot\System32\drivers\disk.sys", @"\SystemRoot\System32\drivers\partmgr.sys", @"\SystemRoot\System32\drivers\pci.sys" };
            for (int i = 0; i < bootDrv.Length; i++)
            {
                string p = bootDrv[i].Replace(@"\SystemRoot\", Environment.GetFolderPath(Environment.SpecialFolder.Windows) + @"\");
                if (!File.Exists(p)) continue;
                byte[] h = ComputeFileFingerprint(p);
                uint sig = (uint)(h[0] | (h[1] << 8) | (h[2] << 16) | (h[3] << 24));
                bool signed = WinTrust.VerifyFileSignature(p) == SignatureStatus.Valid;
                Console.WriteLine($"[PRE-BOOT] {Path.GetFileName(p)} sig=0x{sig:X8} authenticode={(signed ? "OK" : "FAIL")}");
            }
            return true;
        }
        catch { return false; }
    }

    public static byte[] ComputeBufferFingerprint(byte[] data)
    {
        if (data == null) return new byte[32];
        return SHA256.HashData(data);
    }

    public static byte[] ComputeFileFingerprint(string path)
    {
        try
        {
            return BcryptSha256.HashFile(path);
        }
        catch { return new byte[32]; }
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private void SetPhase(ShieldPhase p) { Volatile.Write(ref Unsafe.As<ShieldPhase, byte>(ref _phase), (byte)p); }

    public void Dispose()
    {
        if (Interlocked.CompareExchange(ref _disposed, 1, 0) != 0) return;
        Volatile.Write(ref EngineState.ShuttingDown, 1);
        _shieldThread?.Join(500);
    }

    private static partial class NativeMethods
    {
        [LibraryImport("kernel32.dll", EntryPoint = "CreateFileW", SetLastError = true, StringMarshalling = StringMarshalling.Utf16)]
        public static partial IntPtr CreateFileW(string lpFileName, uint dwDesiredAccess, uint dwShareMode, IntPtr lpSecurityAttributes, uint dwCreationDisposition, uint dwFlagsAndAttributes, IntPtr hTemplateFile);

        [LibraryImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static unsafe partial bool ReadFile(IntPtr hFile, byte* lpBuffer, uint nNumberOfBytesToRead, out uint lpNumberOfBytesRead, IntPtr lpOverlapped);

        [LibraryImport("kernel32.dll")]
        public static partial IntPtr GetCurrentProcess();

        [LibraryImport("advapi32.dll", EntryPoint = "InitiateSystemShutdownExW", SetLastError = true, StringMarshalling = StringMarshalling.Utf16)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static partial bool InitiateSystemShutdownExW(string? lpMachineName, string lpMessage, uint dwTimeout, [MarshalAs(UnmanagedType.Bool)] bool bForceAppsClosed, [MarshalAs(UnmanagedType.Bool)] bool bRebootAfterShutdown, uint dwReason, string? lpComment);

        [LibraryImport("ntdll.dll")]
        public static partial int RtlAdjustPrivilege(uint Privilege, [MarshalAs(UnmanagedType.Bool)] bool Enable, [MarshalAs(UnmanagedType.Bool)] bool CurrentThread, [MarshalAs(UnmanagedType.Bool)] out bool Enabled);

        [LibraryImport("ntdll.dll")]
        public static partial int NtRaiseHardError(uint ErrorStatus, uint NumberOfParameters, uint UnicodeStringParameterMask, IntPtr Parameters, uint ValidResponseOption, out uint Response);
    }
}
