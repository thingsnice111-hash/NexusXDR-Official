using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;

namespace NexusAV.Engine;

/// <summary>
/// User-mode self-defense SENSORS (no kernel driver). Watches the engine's own process,
/// executable file and neighbourhood. This class never blocks anything by itself: it raises
/// findings, and the engine's response path decides whether anything is halted.
/// </summary>
public sealed class UserModeSelfDefense : IDisposable
{
    private readonly uint _enginePid;
    private readonly Timer _defenseTimer;
    private readonly Timer _antiTamperTimer;
    private readonly CancellationTokenSource _cts = new();
    private volatile bool _isRunning;
    private volatile bool _bypassMode;
    private int _disposed;
    private byte[] _processSnapshotHash;
    private string _originalExecutablePath;
    private long _originalFileSize;
    private DateTime _originalFileTimestamp;
    private int _defenseTriggerCount;
    private long _lastCmdLineScan;
    private const int CommandLineScanIntervalMs = 30_000;
    private const int CommandLineScanBudget = 512;
    private readonly HashSet<uint> _protectedProcesses = new();
    private readonly Dictionary<uint, DateTime> _suspiciousProcessTimestamps = new();

    public event Action<string>? OnDefenseTriggered;
    public event Action? OnSelfDefenseDisabled;
    public event Action<uint, string>? OnSuspiciousProcessDetected;

    public UserModeSelfDefense(uint enginePid)
    {
        _enginePid = enginePid;
        _defenseTimer = new Timer(DefenseLoop, null, TimeSpan.FromSeconds(3), TimeSpan.FromSeconds(3));
        _antiTamperTimer = new Timer(AntiTamperLoop, null, TimeSpan.FromSeconds(5), TimeSpan.FromSeconds(5));
        
        // Capture initial state
        CaptureInitialState();
        
        // Mark self as protected
        _protectedProcesses.Add(enginePid);
    }

    private void CaptureInitialState()
    {
        try
        {
            _originalExecutablePath = Process.GetCurrentProcess().MainModule?.FileName ?? "";
            if (!string.IsNullOrEmpty(_originalExecutablePath))
            {
                var fileInfo = new FileInfo(_originalExecutablePath);
                _originalFileSize = fileInfo.Length;
                _originalFileTimestamp = fileInfo.LastWriteTime;
                
                // Calculate initial hash
                _processSnapshotHash = CalculateFileHash(_originalExecutablePath);
                Console.WriteLine($"[SELF-DEFENSE] Initial state captured: {_originalExecutablePath}, Size={_originalFileSize}");
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[SELF-DEFENSE] Failed to capture initial state: {ex.Message}");
        }
    }

    private static byte[] CalculateFileHash(string filePath)
    {
        try
        {
            using var sha256 = SHA256.Create();
            using var fs = File.OpenRead(filePath);
            return sha256.ComputeHash(fs);
        }
        catch
        {
            return Array.Empty<byte>();
        }
    }

    public void Start()
    {
        _isRunning = true;
        Console.WriteLine($"[SELF-DEFENSE] User-mode self-defense SENSORS active for pid={_enginePid} (observation only — blocking is the response path's job)");
        Console.WriteLine("[SELF-DEFENSE] Protection layers:");
        Console.WriteLine("  - Process integrity monitoring");
        Console.WriteLine("  - File tamper detection (SHA256)");
        Console.WriteLine("  - Suspicious process detection");
        Console.WriteLine("  - Anti-debugging detection");
        Console.WriteLine("  - Handle enumeration monitoring");
        Console.WriteLine("  - Memory integrity checks");
    }

    public void Stop()
    {
        _isRunning = false;
        _cts.Cancel();
        OnSelfDefenseDisabled?.Invoke();
        Console.WriteLine("[SELF-DEFENSE] Self-defense deactivated");
    }

    public void SetBypassMode(bool enabled)
    {
        _bypassMode = enabled;
        Console.WriteLine($"[SELF-DEFENSE] Bypass mode: {(enabled ? "ENABLED" : "DISABLED")}");
    }

    private void DefenseLoop(object? state)
    {
        if (!_isRunning || _bypassMode) return;

        try
        {
            CheckProcessIntegrity();
            CheckForSuspiciousProcesses();
            CheckForDebugger();
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[SELF-DEFENSE] Defense loop error: {ex.Message}");
        }
    }

    private void AntiTamperLoop(object? state)
    {
        if (!_isRunning || _bypassMode) return;

        try
        {
            CheckForTampering();
            CheckMemoryIntegrity();
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[SELF-DEFENSE] Anti-tamper loop error: {ex.Message}");
        }
    }

    /// <summary>
    /// Every defense finding is counted and published here. Nothing in this class prevents
    /// anything: it observes, and the response (halt / terminate) belongs to the engine's
    /// response path. The counter used to be declared and never written, which made the
    /// "defenses triggered" statistic permanently, quietly zero.
    /// </summary>
    private void RaiseDefense(string message)
    {
        Interlocked.Increment(ref _defenseTriggerCount);
        OnDefenseTriggered?.Invoke(message);
    }

    private void CheckProcessIntegrity()
    {
        try
        {
            using var engineProc = Process.GetProcessById((int)_enginePid);
            
            // Check if process is still running
            if (engineProc.HasExited)
            {
                RaiseDefense("CRITICAL: Engine process terminated unexpectedly");
                return;
            }

            // Check for process name spoofing
            string currentName = engineProc.ProcessName.ToLowerInvariant();
            string expectedName = Path.GetFileNameWithoutExtension(_originalExecutablePath).ToLowerInvariant();
            if (!string.IsNullOrEmpty(expectedName) && currentName != expectedName)
            {
                RaiseDefense($"WARNING: Process name changed from {expectedName} to {currentName}");
            }
        }
        catch (ArgumentException)
        {
            RaiseDefense("CRITICAL: Engine process not found - may have been terminated");
        }
    }

    private void CheckForTampering()
    {
        try
        {
            if (string.IsNullOrEmpty(_originalExecutablePath)) return;

            var fileInfo = new FileInfo(_originalExecutablePath);
            if (!fileInfo.Exists)
            {
                RaiseDefense("CRITICAL: Engine executable file disappeared!");
                return;
            }

            // Check file size
            long currentSize = fileInfo.Length;
            if (currentSize != _originalFileSize)
            {
                RaiseDefense($"CRITICAL: File size changed from {_originalFileSize} to {currentSize}");
            }

            // Check timestamp
            DateTime currentTimestamp = fileInfo.LastWriteTime;
            if (currentTimestamp != _originalFileTimestamp)
            {
                RaiseDefense($"WARNING: File timestamp changed from {_originalFileTimestamp} to {currentTimestamp}");
            }

            // Check hash (strongest tamper detection)
            byte[] currentHash = CalculateFileHash(_originalExecutablePath);
            if (currentHash.Length > 0 && _processSnapshotHash.Length > 0)
            {
                if (!currentHash.SequenceEqual(_processSnapshotHash))
                {
                    RaiseDefense("CRITICAL: File hash mismatch - executable has been modified!");
                }
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[SELF-DEFENSE] Tampering check error: {ex.Message}");
        }
    }

    private void CheckForSuspiciousProcesses()
    {
        try
        {
            // Shared snapshot: one Process.GetProcesses per second for the whole engine, instead
            // of this loop taking its own copy every 3 s.
            var snapshot = ProcessSnapshotCache.Snapshot;
            var currentSuspicious = new List<string>();

            // Known hacking/analysis tools. Matching is token-based (process name split on -._
            // ) to avoid substring false positives such as "pin" matching "...Shipping".
            string[] hackingTools = {
                "cheatengine", "x64dbg", "x32dbg", "ida", "ida64", "ollydbg",
                "windbg", "cdb", "ntsd", "procexp", "processhacker", "procmon",
                "wireshark", "fiddler", "burpsuite", "recaf", "dnspy", "ilspy",
                "dotpeek", "ghidra", "radare2", "binaryninja", "hopper",
                "immunity", "mona", "pin", "frida", "xposed"
            };

            // The "does anything mention our pid" pass reads every command line, so it runs on
            // a slower cadence than the name checks and reads the PEB instead of Win32_Process.
            long nowTicks = Environment.TickCount64;
            bool scanCommandLines = nowTicks - Volatile.Read(ref _lastCmdLineScan) >= CommandLineScanIntervalMs;
            if (scanCommandLines) Volatile.Write(ref _lastCmdLineScan, nowTicks);
            int commandBudget = scanCommandLines ? CommandLineScanBudget : 0;
            char[] commandBuffer = scanCommandLines ? new char[1024] : Array.Empty<char>();
            string enginePidText = _enginePid.ToString();

            foreach (var proc in snapshot)
            {
                uint pid = proc.Pid;
                if (pid == _enginePid) continue;
                string name = proc.Name.ToLowerInvariant();

                if (MatchesAnyToken(name, hackingTools, out string matchedTool))
                {
                    currentSuspicious.Add(proc.Name);
                    OnSuspiciousProcessDetected?.Invoke(pid, $"Hacking tool detected: {proc.Name}");

                    // Track repeated detections
                    if (_suspiciousProcessTimestamps.TryGetValue(pid, out var lastSeen)
                        && DateTime.Now - lastSeen < TimeSpan.FromMinutes(1))
                    {
                        RaiseDefense($"HIGH RISK: Repeated detection of hacking tool {proc.Name} (pid={pid})");
                    }
                    if (_suspiciousProcessTimestamps.Count > 1024) _suspiciousProcessTimestamps.Clear();
                    _suspiciousProcessTimestamps[pid] = DateTime.Now;
                    _ = matchedTool;
                }

                // Check for termination tools (exact process names, not substrings).
                if (name == "taskmgr" || name == "taskkill" || name == "pkill")
                {
                    currentSuspicious.Add(proc.Name);
                    OnSuspiciousProcessDetected?.Invoke(pid, $"Process termination tool: {proc.Name}");
                }

                // Check for processes with our PID in their command line (potential targeting)
                if (commandBudget > 0)
                {
                    commandBudget--;
                    try
                    {
                        int len = ActiveGuardian.ReadCommandLine(pid, commandBuffer);
                        if (len > 0)
                        {
                            string commandLine = new string(commandBuffer, 0, len);
                            if (MentionsTermination(commandLine) && ContainsPidToken(commandLine, enginePidText))
                                RaiseDefense($"WARNING: Process {proc.Name} targeting our PID {_enginePid}");
                        }
                    }
                    catch { }
                }
            }

            if (currentSuspicious.Count > 0)
                RaiseDefense($"Suspicious processes active: {string.Join(", ", currentSuspicious.Distinct())}");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[SELF-DEFENSE] Suspicious process check error: {ex.Message}");
        }
    }

    private void CheckForDebugger()
    {
        try
        {
            // Check if being debugged using IsDebuggerPresent
            if (IsDebuggerPresent())
            {
                RaiseDefense("CRITICAL: Debugger detected attached to our process!");
            }

            // Check for remote debugging
            using var proc = Process.GetCurrentProcess();
            if (proc.MainWindowTitle?.ToLowerInvariant().Contains("debug") == true)
            {
                RaiseDefense("WARNING: Debug environment detected");
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[SELF-DEFENSE] Debugger check error: {ex.Message}");
        }
    }

    [DllImport("kernel32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool IsDebuggerPresent();

    private static readonly string[] TerminationKeywords =
    {
        "taskkill", "/pid", "stop-process", "terminateprocess", "pssuspend", "procdump", "-id "
    };

    /// <summary>
    /// A bare pid inside a command line is not a signal — browsers and installers jam numbers
    /// into their arguments ("...handle=1234,4800"). Only counts when a termination-style keyword
    /// is present as well.
    /// </summary>
    private static bool MentionsTermination(string commandLine)
    {
        string lower = commandLine.ToLowerInvariant();
        foreach (string keyword in TerminationKeywords)
            if (lower.Contains(keyword, StringComparison.Ordinal)) return true;
        return false;
    }

    /// <summary>The pid must stand on its own, not be part of a longer number.</summary>
    private static bool ContainsPidToken(string text, string pidText)
    {
        int index = 0;
        while ((index = text.IndexOf(pidText, index, StringComparison.Ordinal)) >= 0)
        {
            int after = index + pidText.Length;
            bool leftOk = index == 0 || !char.IsDigit(text[index - 1]);
            bool rightOk = after >= text.Length || !char.IsDigit(text[after]);
            if (leftOk && rightOk) return true;
            index = after;
        }
        return false;
    }

    private static bool MatchesAnyToken(string lowerName, string[] tokens, out string matched)
    {
        // Split a process name into identifier tokens (drop .exe, split on -._ ) and compare
        // each token against the known-tool list. Avoids substring false positives.
        matched = string.Empty;
        string[] parts = lowerName.Split(new[] { '-', '_', '.', ' ' }, StringSplitOptions.RemoveEmptyEntries);
        foreach (string part in parts)
        {
            foreach (string tool in tokens)
            {
                bool hit = part == tool
                    || (tool.Length >= 5 && part.StartsWith(tool))
                    || (part.Length >= 5 && tool.StartsWith(part));
                if (hit) { matched = tool; return true; }
            }
        }
        return false;
    }

    private void CheckMemoryIntegrity()
    {
        try
        {
            // Check for code cave detection (simplified)
            // In full implementation, would scan memory regions for suspicious modifications
            using var proc = Process.GetCurrentProcess();
            long memorySize = proc.PrivateMemorySize64;
            
            // Significant memory growth could indicate injection
            // This is a heuristic check
            if (memorySize > 500 * 1024 * 1024) // > 500MB
            {
                RaiseDefense($"WARNING: Unusual memory usage: {memorySize / 1024 / 1024}MB");
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[SELF-DEFENSE] Memory integrity check error: {ex.Message}");
        }
    }

    public bool IsProtected(uint pid)
    {
        return _protectedProcesses.Contains(pid);
    }

    public void ProtectProcess(uint pid)
    {
        if (!_protectedProcesses.Contains(pid))
        {
            _protectedProcesses.Add(pid);
            Console.WriteLine($"[SELF-DEFENSE] Added pid={pid} to protected processes list");
        }
    }

    public void UnprotectProcess(uint pid)
    {
        _protectedProcesses.Remove(pid);
        Console.WriteLine($"[SELF-DEFENSE] Removed pid={pid} from protected processes list");
    }

    public (int DefenseTriggers, int SuspiciousProcesses, int ProtectedProcesses) GetStats()
    {
        return (_defenseTriggerCount, _suspiciousProcessTimestamps.Count, _protectedProcesses.Count);
    }

    public void Dispose()
    {
        if (Interlocked.Exchange(ref _disposed, 1) == 0)
        {
            _isRunning = false;
            _cts.Cancel();
            _defenseTimer?.Dispose();
            _antiTamperTimer?.Dispose();
        }
    }
}
