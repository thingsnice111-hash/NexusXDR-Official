using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

namespace NexusAV.Engine;

public sealed class RealtimeScanner : IDisposable
{
    private readonly VirusTotalScanner _vtScanner;
    private readonly QuarantineManager _quarantineManager;
    private readonly WhitelistManager? _whitelistManager;
    private readonly ConcurrentQueue<string> _scanQueue = new();
    private readonly CancellationTokenSource _cts = new();
    private readonly Thread _scanThread;
    private readonly Timer _directoryWatchTimer;
    private readonly object _lock = new();
    
    private readonly List<FileSystemWatcher> _watchers = new();
    private readonly HashSet<string> _watchedDirectories = new();
    private readonly HashSet<string> _excludedExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".tmp", ".log", ".bak", ".old", ".temp",
        // JSON-lines files are append-only logs (IDE/agent transcripts) that churn every
        // second; hashing them serves no detection purpose and spams scan events.
        ".jsonl"
    };
    
    private readonly HashSet<string> _trustedPaths = new(StringComparer.OrdinalIgnoreCase)
    {
        @"C:\Windows",
        @"C:\Program Files",
        @"C:\Program Files (x86)",
        @"C:\ProgramData"
    };

    // Busy/churn locations: temp folders and OS-managed package state churn
    // thousands of writes/sec (browser journals, search index DBs). Scanning on
    // every write here caused a runaway scan-event flood (see cooldown below too).
    private static readonly string[] _excludedPathFragments =
    {
        @"\AppData\Local\Temp\",
        @"\AppData\Local\Packages\",
        // Developer dependency trees churn thousands of script files on every build/restore.
        // Malware does not need them; the scan queue does need to stay shallow.
        @"\node_modules\",
        @"\.venv\",
        @"\venv\",
        @"\AppData\Local\npm-cache\",
        @"\AppData\Roaming\npm\"
    };

    // At most one queued scan per file per cooldown window. Without this, every
    // write to an actively-written file (journals, WAL DBs, logs) enqueued a new
    // scan — 180k+ scans/minute for a single file in testing.
    private static readonly TimeSpan PerFileCooldown = TimeSpan.FromSeconds(30);
    private readonly ConcurrentDictionary<string, long> _lastQueuedTicks = new(StringComparer.OrdinalIgnoreCase);

    private volatile bool _isRunning;
    private int _disposed;
    private int _filesScanned;
    private int _threatsDetected;
    private int _knownBadBlocked;
    private int _fingerprintHits;
    private int _disputedHeld;

    /// <summary>Malicious engines at or above this count = confirmed known-bad: block now.</summary>
    public const int KnownBadEngineThreshold = 10;

    /// <summary>Malicious engines at or above this count = probable: quarantine, no containment.</summary>
    public const int ProbableEngineThreshold = 3;

    public event Action<string, VirusTotalResult>? OnScanComplete;
    public event Action<string, string>? OnThreatDetected;
    public event Action<string, string>? OnQuarantineAction;

    /// <summary>Path, malicious count, total engines, what was done. Known-bad tier only.</summary>
    public event Action<string, int, int, string>? OnKnownBadBlocked;

    /// <summary>Path, match kind (exact/same_code/fuzzy), stored sha256, note.</summary>
    public event Action<string, string, string, string>? OnFingerprintHit;

    /// <summary>1–2 engine verdicts held for local corroboration: path, counts, local score, signals.</summary>
    public event Action<string, int, int, int, string>? OnDisputedVerdict;

    /// <summary>
    /// Local, signature-free analyzer used exactly where the cloud cannot help: a hash
    /// VirusTotal has never seen. Set by the engine host; null keeps hash-only behaviour.
    /// </summary>
    public Func<string, ZeroDayVerdict?>? LocalAnalyzer { get; set; }

    /// <summary>Known-bad fingerprint store; null disables local fingerprint blocking.</summary>
    public FingerprintStore? Fingerprints { get; set; }

    /// <summary>Raised for a file the cloud did not judge: path, local score, signal summary.</summary>
    public event Action<string, int, string>? OnZeroDayVerdict;

    public RealtimeScanner(VirusTotalScanner vtScanner, QuarantineManager quarantineManager, WhitelistManager? whitelistManager = null)
    {
        _vtScanner = vtScanner;
        _quarantineManager = quarantineManager;
        _whitelistManager = whitelistManager;
        _scanThread = new Thread(ScanLoop)
        {
            IsBackground = true,
            Name = "Nexus-RealtimeScanner"
        };
        _directoryWatchTimer = new Timer(CheckNewDirectories, null, TimeSpan.FromSeconds(30), TimeSpan.FromSeconds(30));
    }

    public void Start()
    {
        ObjectDisposedException.ThrowIf(_disposed == 1, this);

        lock (_lock)
        {
            if (_isRunning)
                return;

            _isRunning = true;
            _scanThread.Start();

            // Watch common user directories
            WatchDirectory(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile));
            WatchDirectory(Environment.GetFolderPath(Environment.SpecialFolder.Desktop));
            WatchDirectory(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads"));
            WatchDirectory(Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments));

            Console.WriteLine("[REALTIME] Scanner started. Watching directories for new files.");
        }
    }

    public void Stop()
    {
        lock (_lock)
        {
            if (!_isRunning)
                return;

            _isRunning = false;
            _cts.Cancel();

            foreach (var watcher in _watchers)
            {
                watcher.EnableRaisingEvents = false;
                watcher.Dispose();
            }
            _watchers.Clear();
            _watchedDirectories.Clear();
        }

        Console.WriteLine("[REALTIME] Scanner stopped.");
    }

    public void WatchDirectory(string path)
    {
        if (!Directory.Exists(path))
            return;

        lock (_lock)
        {
            if (_watchedDirectories.Contains(path))
                return;

            try
            {
                var watcher = new FileSystemWatcher(path)
                {
                    NotifyFilter = NotifyFilters.FileName | NotifyFilters.Size | NotifyFilters.LastWrite,
                    IncludeSubdirectories = true,
                    EnableRaisingEvents = _isRunning
                };

                watcher.Created += OnFileCreated;
                watcher.Changed += OnFileChanged;
                watcher.Error += OnWatcherError;

                _watchers.Add(watcher);
                _watchedDirectories.Add(path);

                Console.WriteLine($"[REALTIME] Now watching: {path}");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[REALTIME] Failed to watch {path}: {ex.Message}");
            }
        }
    }

    public void QueueFileForScan(string filePath)
    {
        if (!File.Exists(filePath))
            return;

        string ext = Path.GetExtension(filePath);
        if (_excludedExtensions.Contains(ext))
            return;

        // Skip trusted paths
        bool isTrusted = _trustedPaths.Any(trusted => filePath.StartsWith(trusted, StringComparison.OrdinalIgnoreCase));
        if (isTrusted)
            return;

        foreach (string fragment in _excludedPathFragments)
            if (filePath.Contains(fragment, StringComparison.OrdinalIgnoreCase))
                return;

        // User-configured whitelist: skip paths the user explicitly excluded
        if (_whitelistManager != null && _whitelistManager.IsWhitelisted(filePath))
            return;

        // Allowlist, checked before anything expensive. The watcher covers the whole user profile
        // recursively, so without this a browser or IDE write burst feeds thousands of .db, .pak,
        // .node and cache files into SHA-256 hashing — that disk storm is what makes the PC stutter
        // right after the console opens. Only code files and the document types used as lures matter.
        if (!ZeroDayEngine.IsWorthAnalyzing(ext))
            return;

        try
        {
            var fi = new FileInfo(filePath);
            if (fi.Exists && fi.Length > 80L * 1024 * 1024) return; // giant installers/archives: hashing costs more than it tells us
        }
        catch { return; }

        // Per-file cooldown: collapse write bursts (and duplicate watcher events
        // for the same file) into at most one scan per window.
        long now = Environment.TickCount64;
        if (_lastQueuedTicks.TryGetValue(filePath, out long last) &&
            now - last < (long)PerFileCooldown.TotalMilliseconds)
            return;
        _lastQueuedTicks[filePath] = now;

        if (_lastQueuedTicks.Count > 4096)
        {
            long cutoff = now - (long)TimeSpan.FromMinutes(5).TotalMilliseconds;
            foreach (var kv in _lastQueuedTicks)
                if (kv.Value < cutoff) _lastQueuedTicks.TryRemove(kv.Key, out _);
        }

        // Shallow queue: if the single scan thread cannot keep up, new events are dropped rather
        // than accumulating memory and replaying an hour of churn later.
        if (_scanQueue.Count > 1500)
            return;

        _scanQueue.Enqueue(filePath);
    }

    private void OnFileCreated(object sender, FileSystemEventArgs e)
    {
        if (_isRunning)
        {
            QueueFileForScan(e.FullPath);
        }
    }

    private void OnFileChanged(object sender, FileSystemEventArgs e)
    {
        if (_isRunning)
        {
            QueueFileForScan(e.FullPath);
        }
    }

    private void OnWatcherError(object sender, ErrorEventArgs e)
    {
        Console.WriteLine($"[REALTIME] Watcher error: {e.GetException().Message}");
    }

    private void ScanLoop()
    {
        while (!_cts.IsCancellationRequested)
        {
            try
            {
                if (_scanQueue.TryDequeue(out string? filePath))
                {
                    // Sequential on purpose: a fire-and-forget async void spawned an
                    // unbounded parallel scan swarm during bursts (and hammered the
                    // VT rate limit). One at a time keeps the event stream calm.
                    ScanFileAsync(filePath).GetAwaiter().GetResult();
                }
                else
                {
                    Thread.Sleep(100);
                }
            }
            catch (ThreadInterruptedException)
            {
                break;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[REALTIME] Scan loop error: {ex.Message}");
            }
        }
    }

    private static bool IsBusyFileError(string? error)
    {
        if (string.IsNullOrEmpty(error)) return false;
        return error.Contains("being used by another process", StringComparison.OrdinalIgnoreCase)
            || error.Contains("cannot access", StringComparison.OrdinalIgnoreCase)
            || error.Contains("sharing violation", StringComparison.OrdinalIgnoreCase);
    }

    private async Task ScanFileAsync(string filePath)
    {
        try
        {
            // Wait for file to be fully written
            await Task.Delay(500);

            if (!File.Exists(filePath))
                return;

            // Known-bad identities first: one local hash, no cloud quota, works with no network.
            if (Fingerprints != null && Fingerprints.Count > 0)
            {
                var hit = Fingerprints.Lookup(FileFingerprinter.Sha256Of(filePath), "", "", "");
                if (hit is { } known)
                {
                    Interlocked.Increment(ref _filesScanned);
                    Interlocked.Increment(ref _fingerprintHits);
                    string why = $"known-bad fingerprint match ({known.Kind}), recorded as {known.Entry.Source}";
                    Console.WriteLine($"[REALTIME] KNOWN-BAD ON DISK: {filePath} :: {why}");
                    OnFingerprintHit?.Invoke(filePath, known.Kind, known.Entry.Sha256, known.Entry.Note);
                    ContainKnownBad(filePath, why, known.Entry.Sha256, 0, 0, record: false);
                    return;
                }
            }

            var result = await _vtScanner.ScanFileAsync(filePath, uploadIfUnknown: false, _cts.Token);

            // A busy file (locked by its writer) is normal churn, not a failure —
            // publishing these flooded the GUI with SCAN FAILED toasts.
            if (IsBusyFileError(result.ErrorMessage))
                return;

            Interlocked.Increment(ref _filesScanned);

            Console.WriteLine($"[REALTIME] Scanned: {Path.GetFileName(filePath)}");
            OnScanComplete?.Invoke(filePath, result);

            int mc = result.MaliciousCount, tot = result.TotalEngines;

            if (mc >= KnownBadEngineThreshold)
            {
                Interlocked.Increment(ref _threatsDetected);
                Console.WriteLine($"[REALTIME] KNOWN-BAD: {filePath} - {mc}/{tot} {result.DetectionNames}");
                OnThreatDetected?.Invoke(filePath, result.DetectionNames);
                ContainKnownBad(filePath, $"VirusTotal {mc}/{tot}: {result.DetectionNames}",
                    result.SHA256, mc, tot, record: true);
                return;
            }

            if (mc >= ProbableEngineThreshold)
            {
                Interlocked.Increment(ref _threatsDetected);
                Console.WriteLine($"[REALTIME] THREAT DETECTED: {filePath} - {mc}/{tot} {result.DetectionNames}");
                OnThreatDetected?.Invoke(filePath, result.DetectionNames);
                Quarantine(filePath, $"VirusTotal {mc}/{tot}: {result.DetectionNames}");
                return;
            }

            if (mc > 0)
            {
                // One or two engines is noise more often than malware: quarantine only when the
                // local structure engine independently agrees, otherwise report the disagreement.
                var local = LocalAnalyzer?.Invoke(filePath);
                int score = local?.Score ?? 0;
                string signals = local?.SignalText ?? "local analyzer unavailable";
                Interlocked.Increment(ref _disputedHeld);
                Console.WriteLine($"[REALTIME] DISPUTED {mc}/{tot}: {filePath} :: local score {score}");
                OnDisputedVerdict?.Invoke(filePath, mc, tot, score, signals);

                if (local != null && local.IsBlocker)
                {
                    Interlocked.Increment(ref _threatsDetected);
                    OnThreatDetected?.Invoke(filePath, result.DetectionNames);
                    Quarantine(filePath, $"VirusTotal {mc}/{tot} corroborated by local score {score}: {signals}");
                }
                return;
            }

            if (LocalAnalyzer != null &&
                (result.UploadSkipped || tot == 0 || !string.IsNullOrEmpty(result.ErrorMessage)))
            {
                // Zero-day gap: this hash is either unknown to the cloud or the lookup failed, so
                // a clean-looking result here carries NO information. Hand the bytes to the local
                // structure engine instead of pretending the file was cleared.
                var verdict = LocalAnalyzer(filePath);
                if (verdict != null && verdict.IsWatchable)
                {
                    Interlocked.Increment(ref _threatsDetected);
                    Console.WriteLine($"[REALTIME] LOCAL VERDICT {verdict.Score}: {filePath} :: {verdict.SignalText}");
                    OnZeroDayVerdict?.Invoke(filePath, verdict.Score, verdict.SignalText);
                }
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[REALTIME] Failed to scan {filePath}: {ex.Message}");
        }
    }

    private void Quarantine(string filePath, string reason)
    {
        if (_quarantineManager.QuarantineFile(filePath, reason, out _))
        {
            Console.WriteLine($"[REALTIME] Auto-quarantined: {filePath}");
            OnQuarantineAction?.Invoke(filePath, reason);
        }
    }

    /// <summary>
    /// Known-bad tier: remember the identity, quarantine the file and freeze every process whose
    /// image is that file. Halting instead of killing keeps a wrong verdict one Resume away.
    /// </summary>
    private void ContainKnownBad(string filePath, string reason, string sha256, int mc, int tot, bool record)
    {
        if (record && Fingerprints != null)
        {
            var fp = FileFingerprinter.Compute(filePath, "vt-known-bad", reason);
            if (fp != null && Fingerprints.Add(fp))
                Console.WriteLine($"[FP] recorded known-bad sha256={Trunc(fp.Sha256)} imphash={Trunc(fp.ImportHash)} :: {filePath}");
        }

        Quarantine(filePath, reason);

        int halted = HaltProcessesRunningFile(filePath, reason);
        Interlocked.Increment(ref _knownBadBlocked);
        string done = $"{reason}; quarantined; {halted} process(es) halted" +
                      (string.IsNullOrEmpty(sha256) ? "" : $"; sha256={Trunc(sha256)}");
        Console.WriteLine($"[REALTIME] CONTAINED: {filePath} :: {done}");
        OnKnownBadBlocked?.Invoke(filePath, mc, tot, done);
    }

    private static int HaltProcessesRunningFile(string filePath, string reason)
    {
        int halted = 0;
        try
        {
            foreach (var e in ProcessSnapshotCache.Snapshot)
            {
                string img = SafeProcessKiller.ImagePathOf(e.Pid);
                if (img.Length == 0) continue;
                if (!string.Equals(img, filePath, StringComparison.OrdinalIgnoreCase)) continue;
                halted += SafeProcessKiller.HaltOnly(e.Pid, reason);
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[REALTIME] halt sweep error: {ex.Message}");
        }
        return halted;
    }

    private static string Trunc(string s) => s.Length <= 16 ? s : s[..16];

    public (int FingerprintHits, int KnownBadBlocked, int DisputedHeld) GetKnownBadStats() =>
        (_fingerprintHits, _knownBadBlocked, _disputedHeld);

    private void CheckNewDirectories(object? state)
    {
        // Periodically check for new directories in user profile
        if (!_isRunning)
            return;

        try
        {
            string userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
            var subdirs = Directory.GetDirectories(userProfile, "*", SearchOption.TopDirectoryOnly);
            
            foreach (var dir in subdirs)
            {
                // Skip system directories
                string dirName = Path.GetFileName(dir);
                if (dirName.StartsWith(".") || dirName.Equals("AppData", StringComparison.OrdinalIgnoreCase))
                    continue;

                // Junctions / symbolic links (Nabídka Start, Dokumenty, Local Settings…) are
                // Windows known-folder aliases. Reading them throws every sweep and the real
                // target is already watched through the profile watcher, so skip them outright.
                try
                {
                    var attrs = new DirectoryInfo(dir).Attributes;
                    if ((attrs & FileAttributes.ReparsePoint) != 0) continue;
                }
                catch { continue; }

                // The profile watcher is recursive, so a top-level child is already covered.
                // Adding a second watcher doubles every file event.
                string parentProfile = userProfile.TrimEnd('\\');
                if (dir.StartsWith(parentProfile + "\\", StringComparison.OrdinalIgnoreCase) &&
                    dir.IndexOf('\\', parentProfile.Length + 1) < 0)
                    continue;

                WatchDirectory(dir);
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[REALTIME] Directory check error: {ex.Message}");
        }
    }

    public (int FilesScanned, int ThreatsDetected) GetStats()
    {
        return (_filesScanned, _threatsDetected);
    }

    public void Dispose()
    {
        if (Interlocked.Exchange(ref _disposed, 1) == 0)
        {
            Stop();
            _cts.Cancel();
            _cts.Dispose();
            _directoryWatchTimer?.Dispose();
        }
    }
}
