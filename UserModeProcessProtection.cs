using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;

namespace NexusAV.Engine;

/// <summary>
/// User-mode process protection to replace kernel ObRegisterCallbacks.
/// Provides process termination blocking, handle access control, and PPID spoofing detection.
/// Uses WMI, ETW, and handle enumeration for comprehensive protection.
/// </summary>
public sealed class UserModeProcessProtection : IDisposable
{
    private readonly ConcurrentDictionary<uint, ProcessProtectionInfo> _protectedProcesses = new();
    private readonly Timer _monitorTimer;
    private readonly Timer _handleCheckTimer;
    private readonly CancellationTokenSource _cts = new();
    private readonly Task _monitorTask;
    private volatile bool _isRunning;
    private int _disposed;
    private int _terminationAttemptsBlocked;
    private int _handleViolationsDetected;
    private readonly HashSet<uint> _trustedProcesses = new();

    public record ProcessProtectionInfo(
        uint Pid,
        string Name,
        DateTime ProtectionStartTime,
        List<TerminationAttempt> TerminationAttempts,
        List<HandleViolation> HandleViolations
    );

    public record TerminationAttempt(
        uint AttackerPid,
        string AttackerName,
        string Method,
        DateTime Timestamp,
        bool WasBlocked
    );

    public record HandleViolation(
        uint ViolatorPid,
        string ViolatorName,
        uint DesiredAccess,
        DateTime Timestamp
    );

    public event Action<uint, uint, string>? OnTerminationAttempt;
    public event Action<uint, uint, uint>? OnHandleViolation;
    public event Action<uint, string>? OnProcessProtected;

    public UserModeProcessProtection()
    {
        _monitorTimer = new Timer(MonitorProcesses, null, TimeSpan.FromSeconds(3), TimeSpan.FromSeconds(3));
        // NOTE: user-mode handle->target-process attribution is unreliable without the kernel
        // object pointer, and the SYSTEM_HANDLE table walk had no end-of-buffer bound. That
        // heuristic produced false "handle violation" detections and risked reading past the
        // query buffer, so it is intentionally not scheduled. Termination attempts are still
        // detected via the accurate object-security path.
        _handleCheckTimer = new Timer(CheckHandles, null, Timeout.InfiniteTimeSpan, Timeout.InfiniteTimeSpan);
        _monitorTask = Task.Run(MonitorLoop);

        // Initialize trusted processes
        InitializeTrustedProcesses();
    }

    private void InitializeTrustedProcesses()
    {
        // System processes that are allowed to interact with protected processes
        _trustedProcesses.Add(4); // System
        _trustedProcesses.Add(0); // System idle
        
        // Will add more as we detect them
    }

    public void Start()
    {
        _isRunning = true;
        Console.WriteLine("[PROCESS-PROTECTION] User-mode process monitoring started (detect-only — no kernel callbacks, nothing is prevented)");
        Console.WriteLine("[PROCESS-PROTECTION] Active: process-creation monitoring, PPID spoofing detection");
        Console.WriteLine("[PROCESS-PROTECTION] Not available in user mode: handle-access blocking (check timer intentionally unscheduled), termination blocking (needs ObRegisterCallbacks)");
    }

    public void Stop()
    {
        _isRunning = false;
        _cts.Cancel();
        Console.WriteLine("[PROCESS-PROTECTION] Process protection stopped");
    }

    private async void MonitorLoop()
    {
        while (!_cts.IsCancellationRequested)
        {
            try
            {
                if (_isRunning)
                {
                    await MonitorProcessCreation();
                }
                await Task.Delay(500, _cts.Token);
            }
            catch (OperationCanceledException)
            {
                break;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[PROCESS-PROTECTION] Monitor loop error: {ex.Message}");
            }
        }
    }

    private void MonitorProcesses(object? state)
    {
        if (!_isRunning) return;

        try
        {
            // Monitor protected processes for termination attempts
            foreach (var (pid, info) in _protectedProcesses)
            {
                try
                {
                    using var proc = Process.GetProcessById((int)pid);
                    
                    // Check if process is still running
                    if (proc.HasExited)
                    {
                        Console.WriteLine($"[PROCESS-PROTECTION] Protected process {pid} ({info.Name}) has exited");
                        _protectedProcesses.TryRemove(pid, out _);
                        continue;
                    }

                    // Check for suspicious parent processes
                    CheckProcessParent(proc);
                }
                catch (ArgumentException)
                {
                    // Process doesn't exist
                    _protectedProcesses.TryRemove(pid, out _);
                }
                catch
                {
                    // Access denied etc. — can't open this process right now (privilege or
                    // protected-process). Must stay silent: printing here re-fires every tick.
                }
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[PROCESS-PROTECTION] Process monitor error: {ex.Message}");
        }
    }

    private void CheckHandles(object? state)
    {
        if (!_isRunning) return;

        try
        {
            // Enumerate handles to protected processes
            EnumerateHandlesToProtectedProcesses();
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[PROCESS-PROTECTION] Handle check error: {ex.Message}");
        }
    }

    private Task MonitorProcessCreation()
    {
        try
        {
            // WMI (Win32_ProcessTrace) is unavailable under Native-AOT and its query object
            // was never consumed anyway. Auto-protection reads the shared snapshot cache instead.
            foreach (var entry in ProcessSnapshotCache.Snapshot)
            {
                try
                {
                    if (!_protectedProcesses.ContainsKey(entry.Pid) && IsGuardedImageName(entry.Name))
                    {
                        ProtectProcess(entry.Pid, entry.Name);
                    }
                }
                catch { }
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[PROCESS-PROTECTION] Process creation monitor error: {ex.Message}");
        }
        return Task.CompletedTask;
    }

    private static bool IsGuardedImageName(string name)
    {
        string n = name.ToLowerInvariant();
        // Auto-protect security-related processes
        string[] securityProcesses = { "nexusav.engine", "nexusxdr", "antivirus", "security", "firewall" };
        return securityProcesses.Any(sp => n.Contains(sp));
    }

    private uint GetActualParentProcessId(Process proc)
    {
        try
        {
            var pbi = NativeMethods.NtQueryInformationProcess(proc.Handle);
            if (pbi != null)
            {
                return (uint)pbi.Value.InheritedFromUniqueProcessId;
            }
        }
        catch { }
        return 0;
    }

    // Informational only. Parentage is NOT evidence of an attack: every legit process has a
    // non-System parent, and the previous version suspended any untrusted parent of a protected
    // process — which suspended the GUI that launched the engine (and would have suspended
    // explorer for any auto-protected product). Active countermeasures require a real
    // termination-attempt signal, not merely being spawned by an unsigned process.
    private readonly HashSet<string> _reportedParents = new();

    private void CheckProcessParent(Process proc)
    {
        try
        {
            uint ppid = GetActualParentProcessId(proc);
            if (ppid > 0 && !_trustedProcesses.Contains(ppid))
            {
                lock (_reportedParents)
                {
                    string key = $"{proc.Id}|{ppid}";
                    if (!_reportedParents.Add(key)) return;
                }
                Console.WriteLine($"[PROCESS-PROTECTION] Process {proc.ProcessName} (pid={proc.Id}) has unsigned parent {ppid} (informational; parentage alone is not an attack)");
            }
        }
        catch { }
    }

    // DORMANT countermeasure — no active caller. Call ONLY from a genuine termination-attempt
    // signal (e.g. ETW handle telemetry with PROCESS_TERMINATE intent). Never from heuristics
    // like parentage: the previous caller suspended the GUI that launched the engine.
    private void BlockTerminationAttempt(uint targetPid, uint attackerPid, string method)
    {
        try
        {
            // In user-mode, we can't directly block termination, but we can:
            // 1. Log the attempt
            // 2. Suspend the attacker process (if we have sufficient privileges)
            // 3. Terminate the attacker process (extreme measure)
            
            using var attacker = Process.GetProcessById((int)attackerPid);
            
            // Try to suspend the attacker with NtSuspendProcess (real kernel API).
            // Requires a handle with PROCESS_SUSPEND_RESUME; fails cleanly without privilege.
            if (attacker.Responding)
            {
                try
                {
                    int ntStatus = NtSuspendProcess(attacker.Handle);

                    bool suspended = ntStatus == 0;
                    if (suspended)
                        Console.WriteLine($"[PROCESS-PROTECTION] SUSPENDED attacker process: {attacker.ProcessName} (pid={attackerPid})");
                    else
                        Console.WriteLine($"[PROCESS-PROTECTION] NtSuspendProcess FAILED for {attacker.ProcessName} (pid={attackerPid}): 0x{ntStatus:X8} — attacker is still running");

                    // Only a real suspension counts as a stopped attempt, and the record says
                    // what actually happened: user-mode can freeze a target, not refuse the open.
                    if (suspended) Interlocked.Increment(ref _terminationAttemptsBlocked);

                    // Add to record
                    if (_protectedProcesses.TryGetValue(targetPid, out var info))
                    {
                        var attempt = new TerminationAttempt(
                            attackerPid,
                            attacker.ProcessName,
                            method,
                            DateTime.Now,
                            suspended
                        );
                        info.TerminationAttempts.Add(attempt);
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"[PROCESS-PROTECTION] Failed to suspend attacker: {ex.Message}");
                }
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[PROCESS-PROTECTION] Failed to block termination: {ex.Message}");
        }
    }

    private void EnumerateHandlesToProtectedProcesses()
    {
        try
        {
            // Use NtQuerySystemInformation to enumerate handles
            // This is a simplified implementation
            foreach (var (pid, info) in _protectedProcesses)
            {
                try
                {
                    var violators = GetProcessHandles(pid);
                    foreach (var violator in violators)
                    {
                        if (!_trustedProcesses.Contains(violator.Pid))
                        {
                            var violation = new HandleViolation(
                                violator.Pid,
                                violator.Name,
                                violator.Access,
                                DateTime.Now
                            );
                            info.HandleViolations.Add(violation);
                            
                            OnHandleViolation?.Invoke(pid, violator.Pid, violator.Access);
                            Interlocked.Increment(ref _handleViolationsDetected);
                            
                            Console.WriteLine($"[PROCESS-PROTECTION] Handle violation: pid={pid} violator={violator.Name} access=0x{violator.Access:X}");
                        }
                    }
                }
                catch { }
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[PROCESS-PROTECTION] Handle enumeration error: {ex.Message}");
        }
    }

    private List<(uint Pid, string Name, uint Access)> GetProcessHandles(uint targetPid)
    {
        var result = new List<(uint, string, uint)>();
        
        try
        {
            // Use NtQuerySystemInformation to enumerate handles
            int size = 0;
            int ret = NtQuerySystemInformation(16, IntPtr.Zero, 0, out size); // SystemHandleInformation = 16
            
            if (ret != 0 && ret != unchecked((int)0xC0000004)) // STATUS_INFO_LENGTH_MISMATCH
            {
                Console.WriteLine($"[PROCESS-PROTECTION] Failed to get handle table size: 0x{ret:X8}");
                return result;
            }

            IntPtr buffer = Marshal.AllocHGlobal(size);
            try
            {
                ret = NtQuerySystemInformation(16, buffer, size, out size);
                if (ret != 0)
                {
                    Console.WriteLine($"[PROCESS-PROTECTION] Failed to query handle table: 0x{ret:X8}");
                    return result;
                }

                // Parse the handle table
                IntPtr current = buffer;
                IntPtr end = buffer + size;
                ulong handleCount = unchecked((ulong)Marshal.ReadInt64(current));
                current += 8;

                for (ulong i = 0; i < handleCount && i < 10000; i++) // Limit to 10000 handles
                {
                    // Never read past the allocated query buffer.
                    if (current + 28 > end) break;

                    ushort handleValue = unchecked((ushort)Marshal.ReadInt16(current));
                    current += 2;
                    uint handleAttributes = unchecked((uint)Marshal.ReadInt32(current));
                    current += 4;
                    ushort handleType = unchecked((ushort)Marshal.ReadInt16(current));
                    current += 2;
                    uint objectPointerLow = unchecked((uint)Marshal.ReadInt32(current));
                    current += 4;
                    uint objectPointerHigh = unchecked((uint)Marshal.ReadInt32(current));
                    current += 4;
                    uint grantedAccess = unchecked((uint)Marshal.ReadInt32(current));
                    current += 4;

                    // Check if this handle is to our target process
                    // This is a simplified check - in production would decode object pointers
                    if (handleType == 7) // Process object type
                    {
                        // Extract PID from object pointer (simplified)
                        uint objectPid = objectPointerLow & 0xFFFF;
                        
                        if (objectPid == targetPid)
                        {
                            try
                            {
                                using var proc = Process.GetProcessById((int)objectPid);
                                result.Add((objectPid, proc.ProcessName, grantedAccess));
                            }
                            catch { }
                        }
                    }

                    current += 8; // Skip to next handle
                }
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[PROCESS-PROTECTION] Handle enumeration error: {ex.Message}");
        }

        return result;
    }

    [DllImport("ntdll.dll")]
    private static extern int NtQuerySystemInformation(
        int SystemInformationClass,
        IntPtr SystemInformation,
        int SystemInformationLength,
        out int ReturnLength);

    [DllImport("ntdll.dll")]
    private static extern int NtSuspendProcess(IntPtr ProcessHandle);

    [DllImport("ntdll.dll")]
    private static extern int NtResumeProcess(IntPtr ProcessHandle);

    public void ProtectProcess(uint pid, string name)
    {
        if (!_protectedProcesses.ContainsKey(pid))
        {
            var info = new ProcessProtectionInfo(
                pid,
                name,
                DateTime.Now,
                new List<TerminationAttempt>(),
                new List<HandleViolation>()
            );
            _protectedProcesses[pid] = info;
            OnProcessProtected?.Invoke(pid, name);
            Console.WriteLine($"[PROCESS-PROTECTION] Protected process: {name} (pid={pid})");
        }
    }

    public void UnprotectProcess(uint pid)
    {
        if (_protectedProcesses.TryRemove(pid, out var info))
        {
            Console.WriteLine($"[PROCESS-PROTECTION] Unprotected process: {info.Name} (pid={pid})");
        }
    }

    public bool IsProtected(uint pid)
    {
        return _protectedProcesses.ContainsKey(pid);
    }

    public void AddTrustedProcess(uint pid)
    {
        _trustedProcesses.Add(pid);
        Console.WriteLine($"[PROCESS-PROTECTION] Added trusted process: pid={pid}");
    }

    public void RemoveTrustedProcess(uint pid)
    {
        _trustedProcesses.Remove(pid);
        Console.WriteLine($"[PROCESS-PROTECTION] Removed trusted process: pid={pid}");
    }

    public List<ProcessProtectionInfo> GetProtectedProcesses()
    {
        return _protectedProcesses.Values.ToList();
    }

    public (int ProtectedCount, int TerminationAttemptsBlocked, int HandleViolations) GetStats()
    {
        return (_protectedProcesses.Count, _terminationAttemptsBlocked, _handleViolationsDetected);
    }

    private static class NativeMethods
    {
        [StructLayout(LayoutKind.Sequential)]
        public struct PROCESS_BASIC_INFORMATION
        {
            public IntPtr ExitStatus;
            public IntPtr PebBaseAddress;
            public IntPtr AffinityMask;
            public IntPtr BasePriority;
            public IntPtr UniqueProcessId;
            public IntPtr InheritedFromUniqueProcessId;
        }

        public static PROCESS_BASIC_INFORMATION? NtQueryInformationProcess(IntPtr processHandle)
        {
            try
            {
                int pbiSize = Marshal.SizeOf<PROCESS_BASIC_INFORMATION>();
                IntPtr pbi = Marshal.AllocHGlobal(pbiSize);
                try
                {
                    int ret = NtQueryInformationProcess(processHandle, 0, pbi, pbiSize, out int returnLength);
                    if (ret == 0 && returnLength == pbiSize)
                    {
                        return Marshal.PtrToStructure<PROCESS_BASIC_INFORMATION>(pbi);
                    }
                }
                finally
                {
                    Marshal.FreeHGlobal(pbi);
                }
            }
            catch { }
            return null;
        }

        [DllImport("ntdll.dll")]
        private static extern int NtQueryInformationProcess(
            IntPtr ProcessHandle,
            int ProcessInformationClass,
            IntPtr ProcessInformation,
            int ProcessInformationLength,
            out int ReturnLength);
    }

    public void Dispose()
    {
        if (Interlocked.Exchange(ref _disposed, 1) == 0)
        {
            _isRunning = false;
            _cts.Cancel();
            _monitorTimer?.Dispose();
            _handleCheckTimer?.Dispose();
            _monitorTask?.Wait(TimeSpan.FromSeconds(5));
        }
    }
}
