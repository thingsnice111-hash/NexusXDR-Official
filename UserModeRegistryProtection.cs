using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Win32;

namespace NexusAV.Engine;

/// <summary>
/// User-mode registry protection to replace kernel CmRegisterCallbackEx. User mode cannot hook
/// registry writes, so this polls snapshots of sensitive keys and reports changes after the
/// fact (nothing is blocked), plus a BYOVD signal scan over the Services key.
/// </summary>
public sealed class UserModeRegistryProtection : IDisposable
{
    private readonly ConcurrentDictionary<string, RegistryKeyProtection> _protectedKeys = new();
    private readonly Timer _monitorTimer;
    private readonly CancellationTokenSource _cts = new();
    private readonly Task _monitorTask;
    private volatile bool _isRunning;
    private int _disposed;
    private int _registryWriteViolations;
    private readonly Dictionary<string, byte[]> _keySnapshots = new();

    public record RegistryKeyProtection(
        string KeyPath,
        DateTime ProtectionStartTime,
        List<RegistryViolation> Violations,
        bool ReadOnly
    );

    public record RegistryViolation(
        string KeyPath,
        string ValueName,
        uint AttackerPid,
        string AttackerName,
        string Operation,
        DateTime Timestamp,
        bool WasBlocked
    );

    public event Action<string, string, uint, string>? OnRegistryWriteAttempt;
    public event Action<string, string>? OnRegistryKeyProtected;

    // Sensitive registry keys to protect
    private static readonly string[] SensitiveKeys = {
        @"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services",
        @"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control",
        @"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        @"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
        @"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
        @"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options",
        @"HKEY_LOCAL_MACHINE\SOFTWARE\Policies",
        @"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager",
        @"HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        @"HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"
    };

    // BYOVD vulnerable driver signatures
    private static readonly string[] VulnerableDriverSignatures = {
        "RTCore64",
        "DBUtil_2_3",
        "CAPCOM",
        "AsIO",
        "AsIO.sys",
        "mhyprot2",
        "procexp",
        "winring0"
    };

    public UserModeRegistryProtection()
    {
        _monitorTimer = new Timer(MonitorRegistry, null, TimeSpan.FromSeconds(1), TimeSpan.FromSeconds(1));
        _monitorTask = Task.Run(MonitorLoop);
    }

    public void Start()
    {
        _isRunning = true;
        
        // Auto-protect sensitive keys
        foreach (var key in SensitiveKeys)
        {
            ProtectKey(key, true);
        }
        
        Console.WriteLine("[REGISTRY-PROTECTION] User-mode registry protection started");
        Console.WriteLine("[REGISTRY-PROTECTION] Protected keys:");
        foreach (var key in SensitiveKeys)
        {
            Console.WriteLine($"  - {key}");
        }
        Console.WriteLine("[REGISTRY-PROTECTION] Monitoring for: BYOVD attacks, persistence mechanisms, system tampering");
    }

    public void Stop()
    {
        _isRunning = false;
        _cts.Cancel();
        Console.WriteLine("[REGISTRY-PROTECTION] Registry protection stopped");
    }

    private async void MonitorLoop()
    {
        while (!_cts.IsCancellationRequested)
        {
            try
            {
                if (_isRunning)
                {
                    await DetectByovdAttempts();
                }
                await Task.Delay(1000, _cts.Token);
            }
            catch (OperationCanceledException)
            {
                break;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[REGISTRY-PROTECTION] Monitor loop error: {ex.Message}");
            }
        }
    }

    private void MonitorRegistry(object? state)
    {
        if (!_isRunning) return;

        try
        {
            // Check for unauthorized modifications to protected keys
            foreach (var (keyPath, protection) in _protectedKeys)
            {
                try
                {
                    CheckKeyIntegrity(keyPath, protection);
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"[REGISTRY-PROTECTION] Error checking key {keyPath}: {ex.Message}");
                }
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[REGISTRY-PROTECTION] Registry monitor error: {ex.Message}");
        }
    }

    private void CheckKeyIntegrity(string keyPath, RegistryKeyProtection protection)
    {
        try
        {
            using var key = OpenKey(keyPath);
            if (key == null) return;

            // Get current snapshot
            var currentSnapshot = CaptureKeySnapshot(key);
            
            // Compare with previous snapshot
            if (_keySnapshots.ContainsKey(keyPath))
            {
                var previousSnapshot = _keySnapshots[keyPath];
                if (!currentSnapshot.SequenceEqual(previousSnapshot))
                {
                    // Key has been modified
                    Console.WriteLine($"[REGISTRY-PROTECTION] Modification detected in {keyPath}");
                    
                    if (protection.ReadOnly)
                    {
                        // Snapshot polling sees the change AFTER it landed. User-mode has no
                        // registry callback, so nothing was prevented and the writer is unknown
                        // — reporting WasBlocked=true or blaming our own pid would be fiction.
                        Console.WriteLine($"[REGISTRY-PROTECTION] Protected key changed (observed, not prevented): {keyPath}");

                        var violation = new RegistryViolation(
                            keyPath,
                            "Multiple",
                            0,
                            "unknown",
                            "WRITE",
                            DateTime.Now,
                            false
                        );
                        lock (protection.Violations)
                        {
                            if (protection.Violations.Count > 512) protection.Violations.Clear();
                            protection.Violations.Add(violation);
                        }
                        Interlocked.Increment(ref _registryWriteViolations);
                    }
                }
            }
            
            // Update snapshot
            _keySnapshots[keyPath] = currentSnapshot;
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[REGISTRY-PROTECTION] Error checking key integrity: {ex.Message}");
        }
    }

    /// <summary>Opens a full "HKEY_...\path" string under the matching hive.</summary>
    private static RegistryKey? OpenKey(string keyPath)
    {
        const string hklm = @"HKEY_LOCAL_MACHINE\";
        const string hkcu = @"HKEY_CURRENT_USER\";
        const string hku = @"HKEY_USERS\";
        const string hkcr = @"HKEY_CLASSES_ROOT\";
        const string hkcc = @"HKEY_CURRENT_CONFIG\";

        if (keyPath.StartsWith(hklm, StringComparison.OrdinalIgnoreCase))
            return Registry.LocalMachine.OpenSubKey(keyPath.Substring(hklm.Length), writable: false);
        if (keyPath.StartsWith(hkcu, StringComparison.OrdinalIgnoreCase))
            return Registry.CurrentUser.OpenSubKey(keyPath.Substring(hkcu.Length), writable: false);
        if (keyPath.StartsWith(hku, StringComparison.OrdinalIgnoreCase))
            return Registry.Users.OpenSubKey(keyPath.Substring(hku.Length), writable: false);
        if (keyPath.StartsWith(hkcr, StringComparison.OrdinalIgnoreCase))
            return Registry.ClassesRoot.OpenSubKey(keyPath.Substring(hkcr.Length), writable: false);
        if (keyPath.StartsWith(hkcc, StringComparison.OrdinalIgnoreCase))
            return Registry.CurrentConfig.OpenSubKey(keyPath.Substring(hkcc.Length), writable: false);
        return null;
    }

    private byte[] CaptureKeySnapshot(RegistryKey key)
    {
        try
        {
            using var ms = new System.IO.MemoryStream();
            using var writer = new System.IO.BinaryWriter(ms);
            
            // Capture all value names and data
            foreach (var valueName in key.GetValueNames())
            {
                writer.Write(valueName);
                var value = key.GetValue(valueName);
                if (value is byte[] bytes)
                {
                    writer.Write(bytes.Length);
                    writer.Write(bytes);
                }
                else if (value is string str)
                {
                    writer.Write(str);
                }
                else if (value is int i)
                {
                    writer.Write(i);
                }
            }
            
            return ms.ToArray();
        }
        catch
        {
            return Array.Empty<byte>();
        }
    }

    // BYOVD hits are reported once per (service, signature) and re-armed only if the
    // signature disappears — otherwise the 1s scan re-flagged the same OEM drivers forever.
    private readonly HashSet<string> _reportedByovd = new();
    private readonly object _byovdGate = new();
    private long _lastByovdScan;
    private const int ByovdScanIntervalMs = 15_000;

    private async Task DetectByovdAttempts()
    {
        try
        {
            // Enumeration of every service key is not something to do every second.
            long now = Environment.TickCount64;
            if (now - Volatile.Read(ref _lastByovdScan) < ByovdScanIntervalMs) return;
            Volatile.Write(ref _lastByovdScan, now);

            // Check for BYOVD driver signatures in registry
            using var servicesKey = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services");
            if (servicesKey == null) return;

            var seenThisPass = new HashSet<string>();

            foreach (var serviceName in servicesKey.GetSubKeyNames())
            {
                try
                {
                    using var serviceKey = servicesKey.OpenSubKey(serviceName);
                    if (serviceKey == null) continue;

                    var imagePath = serviceKey.GetValue("ImagePath")?.ToString();

                    if (imagePath != null)
                    {
                        foreach (var signature in VulnerableDriverSignatures)
                        {
                            if (imagePath.Contains(signature, StringComparison.OrdinalIgnoreCase))
                            {
                                string key = serviceName + "|" + signature;
                                seenThisPass.Add(key);
                                bool isNew;
                                lock (_byovdGate)
                                {
                                    isNew = _reportedByovd.Add(key);
                                }
                                if (!isNew) continue;

                                Console.WriteLine($"[REGISTRY-PROTECTION] BYOVD ATTACK DETECTED: {serviceName} contains vulnerable driver signature {signature}");

                                var violation = new RegistryViolation(
                                    $@"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\{serviceName}",
                                    "ImagePath",
                                    0,
                                    "unknown",
                                    "BYOVD_INSTALLATION",
                                    DateTime.Now,
                                    false
                                );

                                if (_protectedKeys.TryGetValue(@"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services", out var prot))
                                {
                                    lock (prot.Violations)
                                    {
                                        if (prot.Violations.Count > 512) prot.Violations.Clear();
                                        prot.Violations.Add(violation);
                                    }
                                }

                                Interlocked.Increment(ref _registryWriteViolations);
                            }
                        }
                    }
                }
                catch { }
            }

            lock (_byovdGate)
            {
                _reportedByovd.RemoveWhere(k => !seenThisPass.Contains(k));
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[REGISTRY-PROTECTION] BYOVD detection error: {ex.Message}");
        }
    }

    public void ProtectKey(string keyPath, bool readOnly = true)
    {
        if (!_protectedKeys.ContainsKey(keyPath))
        {
            var protection = new RegistryKeyProtection(
                keyPath,
                DateTime.Now,
                new List<RegistryViolation>(),
                readOnly
            );
            _protectedKeys[keyPath] = protection;
            OnRegistryKeyProtected?.Invoke(keyPath, readOnly ? "READ_ONLY" : "MONITOR");
            Console.WriteLine($"[REGISTRY-PROTECTION] Protected key: {keyPath} (mode={(readOnly ? "READ_ONLY" : "MONITOR")})");
        }
    }

    public void UnprotectKey(string keyPath)
    {
        if (_protectedKeys.TryRemove(keyPath, out _))
        {
            _keySnapshots.Remove(keyPath);
            Console.WriteLine($"[REGISTRY-PROTECTION] Unprotected key: {keyPath}");
        }
    }

    public bool IsProtected(string keyPath)
    {
        return _protectedKeys.ContainsKey(keyPath);
    }

    public List<RegistryKeyProtection> GetProtectedKeys()
    {
        return _protectedKeys.Values.ToList();
    }

    public (int ProtectedKeys, int Violations, int WriteViolations) GetStats()
    {
        int totalViolations = _protectedKeys.Values.Sum(p => p.Violations.Count);
        return (_protectedKeys.Count, totalViolations, _registryWriteViolations);
    }

    public void Dispose()
    {
        if (Interlocked.Exchange(ref _disposed, 1) == 0)
        {
            _isRunning = false;
            _cts.Cancel();
            _monitorTimer?.Dispose();
            _monitorTask?.Wait(TimeSpan.FromSeconds(5));
        }
    }
}
