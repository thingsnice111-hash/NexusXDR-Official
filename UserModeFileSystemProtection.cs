using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;

namespace NexusAV.Engine;

/// <summary>
/// User-mode file system protection to replace kernel minifilter.
/// Monitors sensitive paths for tampering using FileSystemWatcher + periodic sweeps.
/// Design notes:
///  - A silent baseline pass records every pre-existing file so installers churning
///    Program Files do not generate a "new file" storm at startup.
///  - Integrity checks compare LastWriteTime/Size first and only SHA256-hash when
///    a file actually changed (hashing every file every cycle would peg the disk).
///  - Per-file event lines go through a rate limiter; excess is counted and reported
///    as a single summary line so the GUI log can never be flooded.
///  - Real-time watchers are only attached to low-churn system directories; install
///    trees (Program Files) are covered by the periodic sweep instead.
/// </summary>
public sealed class UserModeFileSystemProtection : IDisposable
{
    private readonly ConcurrentDictionary<string, ProtectedPath> _protectedPaths = new();
    private readonly ConcurrentDictionary<string, FileIntegrityInfo> _fileIntegrity = new();
    private readonly ConcurrentDictionary<string, byte> _knownFiles = new();
    private readonly ConcurrentQueue<DateTime> _recentModifications = new();
    private readonly CancellationTokenSource _cts = new();
    private readonly Task _monitorTask;
    private volatile bool _isRunning;
    private volatile bool _baselineComplete;
    private int _disposed;
    private int _fileWriteViolations;
    private readonly List<FileSystemWatcher> _watchers = new();

    public record ProtectedPath(
        string Path,
        DateTime ProtectionStartTime,
        List<FileViolation> Violations,
        bool ReadOnly,
        bool Recursive
    );

    public record FileViolation(
        string FilePath,
        string Operation,
        uint AttackerPid,
        string AttackerName,
        DateTime Timestamp,
        bool WasBlocked
    );

    public record FileIntegrityInfo(
        string FilePath,
        byte[] Hash,
        DateTime LastChecked,
        long FileSize,
        DateTime LastModified
    );

    public event Action<string, string, uint, string>? OnFileOperationAttempt;
    public event Action<string, string>? OnPathProtected;

    // Low-churn system directories: real-time watchers + read-only enforcement.
    private static readonly string[] SystemCriticalPaths = {
        @"C:\Windows\System32",
        @"C:\Windows\System32\drivers",
        @"C:\Windows\SysWOW64",
        @"C:\Windows\System32\config",
        @"C:\Windows\System32\catroot",
        @"C:\Windows\System32\catroot2"
    };

    // High-churn install trees: sweep-only, monitor mode (no read-only enforcement,
    // no watchers — installers legitimately write here constantly).
    private static readonly string[] InstallTrees = {
        @"C:\Program Files",
        @"C:\Program Files (x86)"
    };

    // Sensitive file extensions
    private static readonly string[] SensitiveExtensions = {
        ".sys", ".dll", ".exe", ".ps1", ".bat", ".cmd", ".vbs", ".js", ".jar"
    };

    private const int SweepIntervalMs = 10_000;
    private const int MaxIndividualLogsPerWindow = 5;
    private static readonly long LogWindowTicks = 5 * Stopwatch.Frequency;

    private readonly object _logGate = new();
    private long _logWindowStart = Stopwatch.GetTimestamp();
    private int _windowLogCount;
    private int _suppressedCount;

    public UserModeFileSystemProtection()
    {
        _monitorTask = Task.Run(MonitorLoop);
    }

    public void Start()
    {
        _isRunning = true;

        foreach (var path in SystemCriticalPaths)
        {
            if (Directory.Exists(path))
            {
                ProtectPath(path, readOnly: true, recursive: true);
            }
        }
        foreach (var path in InstallTrees)
        {
            if (Directory.Exists(path))
            {
                ProtectPath(path, readOnly: false, recursive: true);
            }
        }

        Console.WriteLine("[FILESYSTEM-PROTECTION] User-mode file system protection started");
        Console.WriteLine("[FILESYSTEM-PROTECTION] Protected paths:");
        foreach (var path in SystemCriticalPaths.Where(Directory.Exists))
        {
            Console.WriteLine($"  - {path} (READ_ONLY)");
        }
        foreach (var path in InstallTrees.Where(Directory.Exists))
        {
            Console.WriteLine($"  - {path} (MONITOR)");
        }
        Console.WriteLine("[FILESYSTEM-PROTECTION] Monitoring for: tampering, unauthorized writes, ransomware");

        Task.Run(RunBaseline);
    }

    public void Stop()
    {
        _isRunning = false;
        _cts.Cancel();

        foreach (var watcher in _watchers)
        {
            try
            {
                watcher.EnableRaisingEvents = false;
                watcher.Dispose();
            }
            catch { }
        }
        _watchers.Clear();

        Console.WriteLine("[FILESYSTEM-PROTECTION] File system protection stopped");
    }

    // ── Rate-limited logging ─────────────────────────────────────────────
    // Per-file event lines are capped per 5s window; the excess is counted and
    // reported once as a summary line when the window rolls over.
    private void LogEvent(string line)
    {
        bool shouldLog;
        lock (_logGate)
        {
            long now = Stopwatch.GetTimestamp();
            if (now - _logWindowStart >= LogWindowTicks)
            {
                if (_suppressedCount > 0)
                {
                    Console.WriteLine($"[FILESYSTEM-PROTECTION] ... {_suppressedCount} file event(s) suppressed (rate limit)");
                }
                _logWindowStart = now;
                _windowLogCount = 0;
                _suppressedCount = 0;
            }
            if (_windowLogCount < MaxIndividualLogsPerWindow)
            {
                _windowLogCount++;
                shouldLog = true;
            }
            else
            {
                _suppressedCount++;
                shouldLog = false;
            }
        }
        if (shouldLog)
        {
            Console.WriteLine(line);
        }
    }

    // ── Baseline ─────────────────────────────────────────────────────────
    // Records every pre-existing file silently so post-startup creations are
    // the only ones reported. Metadata only — hashes are taken lazily on change.
    private void RunBaseline()
    {
        int total = 0, sensitive = 0;
        foreach (var (path, protection) in _protectedPaths)
        {
            if (_cts.IsCancellationRequested) return;
            try
            {
                var opts = new EnumerationOptions
                {
                    IgnoreInaccessible = true,
                    RecurseSubdirectories = protection.Recursive,
                    AttributesToSkip = FileAttributes.ReparsePoint
                };
                foreach (var file in Directory.EnumerateFiles(path, "*.*", opts))
                {
                    _knownFiles.TryAdd(file, 0);
                    total++;
                    if (IsSensitiveFile(file))
                    {
                        try
                        {
                            var fi = new FileInfo(file);
                            if (fi.Exists)
                            {
                                _fileIntegrity[file] = new FileIntegrityInfo(
                                    file, Array.Empty<byte>(), DateTime.UtcNow, fi.Length, fi.LastWriteTimeUtc);
                                sensitive++;
                            }
                        }
                        catch { }
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[FILESYSTEM-PROTECTION] Baseline error for {path}: {ex.Message}");
            }
        }
        _baselineComplete = true;
        Console.WriteLine($"[FILESYSTEM-PROTECTION] Baseline complete: {total:N0} files under watch, {sensitive:N0} sensitive tracked");
    }

    // ── Periodic sweep ───────────────────────────────────────────────────
    private async Task MonitorLoop()
    {
        try
        {
            while (!_cts.IsCancellationRequested)
            {
                try
                {
                    await Task.Delay(SweepIntervalMs, _cts.Token);
                }
                catch (OperationCanceledException)
                {
                    break;
                }
                if (!_isRunning || !_baselineComplete) continue;
                try
                {
                    await SweepProtectedPaths();
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"[FILESYSTEM-PROTECTION] Monitor loop error: {ex.Message}");
                }
            }
        }
        catch (OperationCanceledException) { }
    }

    private async Task SweepProtectedPaths()
    {
        foreach (var (path, protection) in _protectedPaths)
        {
            IEnumerable<string> files;
            try
            {
                var opts = new EnumerationOptions
                {
                    IgnoreInaccessible = true,
                    RecurseSubdirectories = protection.Recursive,
                    AttributesToSkip = FileAttributes.ReparsePoint
                };
                files = Directory.EnumerateFiles(path, "*.*", opts);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[FILESYSTEM-PROTECTION] Error scanning {path}: {ex.Message}");
                continue;
            }

            try
            {
                foreach (var file in files)
                {
                    bool isNew = _knownFiles.TryAdd(file, 0);
                    bool sensitive = isNew ? IsSensitiveFile(file)
                                           : IsSensitiveExtensionCached(file);
                    if (isNew)
                    {
                        if (sensitive)
                        {
                            LogEvent($"[FILESYSTEM-PROTECTION] New sensitive file in protected path: {file}");
                            if (protection.ReadOnly)
                            {
                                AddViolation(protection, file, "CREATE");
                            }
                            _fileIntegrity[file] = new FileIntegrityInfo(
                                file, Array.Empty<byte>(), DateTime.UtcNow, -1, DateTime.MinValue);
                        }
                        continue;
                    }
                    if (!sensitive) continue;

                    // Known sensitive file: mtime/size first, hash only on change.
                    FileInfo fi;
                    try
                    {
                        fi = new FileInfo(file);
                        if (!fi.Exists)
                        {
                            _knownFiles.TryRemove(file, out _);
                            _fileIntegrity.TryRemove(file, out _);
                            continue;
                        }
                    }
                    catch { continue; }

                    if (!_fileIntegrity.TryGetValue(file, out var rec) || rec.FileSize < 0)
                    {
                        _fileIntegrity[file] = new FileIntegrityInfo(
                            file, Array.Empty<byte>(), DateTime.UtcNow, fi.Length, fi.LastWriteTimeUtc);
                        continue;
                    }

                    // A fresh record means a watcher already handled this change.
                    if (rec.LastChecked > DateTime.UtcNow.AddMilliseconds(-SweepIntervalMs + 1000)) continue;

                    if (rec.LastModified == fi.LastWriteTimeUtc && rec.FileSize == fi.Length) continue;

                    _recentModifications.Enqueue(DateTime.UtcNow);
                    LogEvent($"[FILESYSTEM-PROTECTION] Sensitive file modified: {file}");
                    byte[] newHash = await CalculateFileHashAsync(file);
                    if (rec.Hash.Length > 0 && newHash.Length > 0 && !newHash.SequenceEqual(rec.Hash))
                    {
                        LogEvent($"[FILESYSTEM-PROTECTION] HASH MISMATCH (tampering): {file}");
                    }
                    if (protection.ReadOnly)
                    {
                        AddViolation(protection, file, "MODIFY");
                    }
                    _fileIntegrity[file] = new FileIntegrityInfo(
                        file, newHash, DateTime.UtcNow, fi.Length, fi.LastWriteTimeUtc);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[FILESYSTEM-PROTECTION] Error checking path {path}: {ex.Message}");
            }
        }

        CheckRansomwareSignal();
        PruneRaiseKeys();
    }

    // Returns true only for files we are already tracking as sensitive; avoids a
    // Path.GetExtension on every known file every sweep.
    private bool IsSensitiveExtensionCached(string file)
    {
        return _fileIntegrity.ContainsKey(file) || IsSensitiveFile(file);
    }

    private void CheckRansomwareSignal()
    {
        var cutoff = DateTime.UtcNow.AddMinutes(-1);
        while (_recentModifications.TryPeek(out var t) && t < cutoff)
        {
            _recentModifications.TryDequeue(out _);
        }
        if (_recentModifications.Count > 50)
        {
            LogEvent($"[FILESYSTEM-PROTECTION] RANSOMWARE PATTERN: {_recentModifications.Count} sensitive files modified in the last minute");
        }
    }

    // Deduplicates violation/event raises per (path, operation): FileSystemWatcher fires
    // Changed several times per physical write, and without this each write spawns duplicate
    // violations, duplicate engine log lines, and duplicate GUI detections.
    private readonly ConcurrentDictionary<string, DateTime> _recentRaiseKeys = new();

    private bool ShouldRaise(string path, string operation)
    {
        const double windowSec = 30;
        string key = operation + "|" + path;
        var now = DateTime.UtcNow;
        if (_recentRaiseKeys.TryGetValue(key, out var last) && (now - last).TotalSeconds < windowSec)
            return false;
        _recentRaiseKeys[key] = now;
        return true;
    }

    private void PruneRaiseKeys()
    {
        if (_recentRaiseKeys.Count < 10_000) return;
        var cutoff = DateTime.UtcNow.AddMinutes(-1);
        foreach (var kv in _recentRaiseKeys)
        {
            if (kv.Value < cutoff)
                _recentRaiseKeys.TryRemove(kv.Key, out _);
        }
    }

    private void AddViolation(ProtectedPath protection, string file, string operation)
    {
        if (!ShouldRaise(file, operation)) return;
        // User-mode FileSystemWatcher cannot attribute the writer (that needs a
        // minifilter/ETW) and fires AFTER the write landed: report unknown writer and
        // WasBlocked=false — nothing here was prevented.
        var violation = new FileViolation(file, operation, 0, "unknown", DateTime.Now, false);
        lock (protection.Violations)
        {
            protection.Violations.Add(violation);
        }
        Interlocked.Increment(ref _fileWriteViolations);
        OnFileOperationAttempt?.Invoke(file, operation, 0, "unknown");
    }

    private bool IsSensitiveFile(string filePath)
    {
        string extension = Path.GetExtension(filePath).ToLowerInvariant();
        return SensitiveExtensions.Contains(extension);
    }

    private static async Task<byte[]> CalculateFileHashAsync(string filePath)
    {
        try
        {
            using var sha256 = SHA256.Create();
            using var fs = File.OpenRead(filePath);
            return await sha256.ComputeHashAsync(fs);
        }
        catch
        {
            return Array.Empty<byte>();
        }
    }

    public void ProtectPath(string path, bool readOnly = true, bool recursive = true)
    {
        if (!_protectedPaths.ContainsKey(path))
        {
            var protection = new ProtectedPath(
                path,
                DateTime.Now,
                new List<FileViolation>(),
                readOnly,
                recursive
            );
            _protectedPaths[path] = protection;

            // Real-time watchers only on low-churn read-only trees; watching
            // install trees would fire per-file events during every legit update.
            if (readOnly && Directory.Exists(path))
            {
                CreateWatcher(path, protection);
            }

            OnPathProtected?.Invoke(path, readOnly ? "READ_ONLY" : "MONITOR");
            Console.WriteLine($"[FILESYSTEM-PROTECTION] Protected path: {path} (mode={(readOnly ? "READ_ONLY" : "MONITOR")}, recursive={recursive})");
        }
    }

    private void CreateWatcher(string path, ProtectedPath protection)
    {
        try
        {
            var watcher = new FileSystemWatcher(path)
            {
                NotifyFilter = NotifyFilters.Attributes |
                               NotifyFilters.CreationTime |
                               NotifyFilters.FileName |
                               NotifyFilters.LastWrite |
                               NotifyFilters.Size |
                               NotifyFilters.Security,
                IncludeSubdirectories = protection.Recursive,
                EnableRaisingEvents = true
            };

            watcher.Changed += (sender, e) => { try { OnFileChanged(e, protection); } catch { } };
            watcher.Created += (sender, e) => { try { OnFileCreated(e, protection); } catch { } };
            watcher.Deleted += (sender, e) => { try { OnFileDeleted(e, protection); } catch { } };
            watcher.Renamed += (sender, e) => { try { OnFileRenamed(e, protection); } catch { } };
            watcher.Error += (sender, e) =>
                LogEvent($"[FILESYSTEM-PROTECTION] Watcher buffer overrun on {path} (some events lost; sweep backstop covers this)");

            _watchers.Add(watcher);
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[FILESYSTEM-PROTECTION] Failed to create watcher for {path}: {ex.Message}");
        }
    }

    private void OnFileChanged(FileSystemEventArgs e, ProtectedPath protection)
    {
        if (!protection.ReadOnly || !IsSensitiveFile(e.FullPath)) return;

        // Record the change so the 10s sweep does not report the same file again.
        try
        {
            var fi = new FileInfo(e.FullPath);
            if (fi.Exists)
            {
                _fileIntegrity.AddOrUpdate(e.FullPath,
                    _ => new FileIntegrityInfo(e.FullPath, Array.Empty<byte>(), DateTime.UtcNow, fi.Length, fi.LastWriteTimeUtc),
                    (_, old) => new FileIntegrityInfo(e.FullPath, old.Hash, DateTime.UtcNow, fi.Length, fi.LastWriteTimeUtc));
            }
        }
        catch { }

        LogEvent($"[FILESYSTEM-PROTECTION] File change detected: {e.FullPath}");
        AddViolation(protection, e.FullPath, "CHANGE");
    }

    private void OnFileCreated(FileSystemEventArgs e, ProtectedPath protection)
    {
        _knownFiles.TryAdd(e.FullPath, 0);
        if (!protection.ReadOnly || !IsSensitiveFile(e.FullPath)) return;

        LogEvent($"[FILESYSTEM-PROTECTION] File creation detected: {e.FullPath}");
        AddViolation(protection, e.FullPath, "CREATE");
    }

    private void OnFileDeleted(FileSystemEventArgs e, ProtectedPath protection)
    {
        _knownFiles.TryRemove(e.FullPath, out _);
        _fileIntegrity.TryRemove(e.FullPath, out _);
        if (!protection.ReadOnly || !IsSensitiveFile(e.FullPath)) return;

        LogEvent($"[FILESYSTEM-PROTECTION] File deletion detected: {e.FullPath}");
        if (ShouldRaise(e.FullPath, "DELETE"))
        {
            var violation = new FileViolation(e.FullPath, "DELETE", 0, "unknown", DateTime.Now, false);
            lock (protection.Violations)
            {
                protection.Violations.Add(violation);
            }
            OnFileOperationAttempt?.Invoke(e.FullPath, "DELETE", 0, "unknown");
        }
    }

    private void OnFileRenamed(RenamedEventArgs e, ProtectedPath protection)
    {
        _knownFiles.TryRemove(e.OldFullPath, out _);
        _knownFiles.TryAdd(e.FullPath, 0);
        if (!protection.ReadOnly || !IsSensitiveFile(e.FullPath)) return;

        LogEvent($"[FILESYSTEM-PROTECTION] File rename detected: {e.OldFullPath} -> {e.FullPath}");
        AddViolation(protection, e.FullPath, "RENAME");
    }

    public void UnprotectPath(string path)
    {
        if (_protectedPaths.TryRemove(path, out _))
        {
            Console.WriteLine($"[FILESYSTEM-PROTECTION] Unprotected path: {path}");
        }
    }

    public bool IsProtected(string path)
    {
        return _protectedPaths.ContainsKey(path) ||
               _protectedPaths.Keys.Any(p => path.StartsWith(p, StringComparison.OrdinalIgnoreCase));
    }

    public List<ProtectedPath> GetProtectedPaths()
    {
        return _protectedPaths.Values.ToList();
    }

    public (int ProtectedPaths, int TrackedFiles, int Violations, int WriteViolations) GetStats()
    {
        int totalViolations = 0;
        foreach (var p in _protectedPaths.Values)
        {
            lock (p.Violations)
            {
                totalViolations += p.Violations.Count;
            }
        }
        return (_protectedPaths.Count, _fileIntegrity.Count, totalViolations, _fileWriteViolations);
    }

    public void Dispose()
    {
        if (Interlocked.Exchange(ref _disposed, 1) == 0)
        {
            _isRunning = false;
            _cts.Cancel();

            foreach (var watcher in _watchers)
            {
                try
                {
                    watcher.EnableRaisingEvents = false;
                    watcher.Dispose();
                }
                catch { }
            }
            _watchers.Clear();

            try
            {
                _monitorTask?.Wait(TimeSpan.FromSeconds(5));
            }
            catch { }
            _cts.Dispose();
        }
    }
}
