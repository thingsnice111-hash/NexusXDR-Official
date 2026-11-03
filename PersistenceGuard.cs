using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Threading;

namespace NexusAV.Engine;

/// <summary>
/// User-mode persistence watcher. Run/RunOnce keys are already covered by
/// <see cref="UserModeRegistryProtection"/>; this module covers the two remaining
/// file-based persistence surfaces:
///   1. the Task Scheduler definition directory (%SystemRoot%\System32\Tasks —
///      best-effort, needs read access; the service writes one XML file per task), and
///   2. the per-user and common Startup folders.
///
/// It reports only REAL file events observed after engine start, and only when the new
/// task's command payload or the dropped startup file looks hostile (pointing into
/// temp/downloads/public, encoded or hidden PowerShell, LOLBin chains) — everything else
/// is ignored so installers that legitimately register tasks do not spam the feed.
/// </summary>
public sealed class PersistenceGuard : IDisposable
{
    private const int ReportCooldownMs = 3_600_000;

    private readonly List<FileSystemWatcher> _watchers = new();
    private readonly ConcurrentQueue<(string path, string kind)> _pending = new();
    private readonly Dictionary<string, long> _reported = new(StringComparer.OrdinalIgnoreCase);
    private Thread? _thread;
    private Thread? _pollThread;
    private HashSet<string>? _taskBaseline;
    private int _disposed;

    public int TotalFindings;

    public void Start()
    {
        string win = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
        bool tasksWatched = Watch(Path.Combine(win, "System32", "Tasks"), "task", subdirs: true);
        Watch(Environment.GetFolderPath(Environment.SpecialFolder.Startup), "startup", subdirs: false);
        Watch(Environment.GetFolderPath(Environment.SpecialFolder.CommonStartup), "startup", subdirs: false);

        _thread = new Thread(Loop) { IsBackground = true, Name = "Nexus-Persistence", Priority = ThreadPriority.BelowNormal };
        _thread.Start();

        // The Tasks directory needs admin read access. Without it, fall back to polling
        // `schtasks /query` (works unelevated via the Task Scheduler RPC service).
        if (!tasksWatched)
        {
            _pollThread = new Thread(PollTasksLoop) { IsBackground = true, Name = "Nexus-PersistencePoll", Priority = ThreadPriority.BelowNormal };
            _pollThread.Start();
        }
        if (_watchers.Count == 0 && tasksWatched == false)
            Console.WriteLine("[PERSIST] no watchable persistence locations (access denied beyond user Startup)");
    }

    private bool Watch(string dir, string kind, bool subdirs)
    {
        try
        {
            if (string.IsNullOrEmpty(dir) || !Directory.Exists(dir)) return false;
            var w = new FileSystemWatcher(dir)
            {
                IncludeSubdirectories = subdirs,
                Filter = "*",
                NotifyFilter = NotifyFilters.FileName | NotifyFilters.LastWrite,
                InternalBufferSize = 64 * 1024
            };
            w.Created += (_, e) => _pending.Enqueue((e.FullPath, kind));
            w.Changed += (_, e) => _pending.Enqueue((e.FullPath, kind));
            w.Renamed += (_, e) => _pending.Enqueue((e.FullPath, kind));
            w.Error += (_, e) => Console.WriteLine($"[PERSIST] watcher error on {dir}: {e.GetException().Message}");
            w.EnableRaisingEvents = true;
            _watchers.Add(w);
            Console.WriteLine($"[PERSIST] watching {dir} ({kind})");
            return true;
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[PERSIST] cannot watch {dir}: {ex.Message}");
            return false;
        }
    }

    private void Loop()
    {
        while (Volatile.Read(ref _disposed) == 0 && Volatile.Read(ref EngineState.ShuttingDown) == 0)
        {
            bool any = false;
            int budget = 32;
            while (budget-- > 0 && _pending.TryDequeue(out var item))
            {
                any = true;
                try { Inspect(item.path, item.kind); }
                catch (Exception ex) { Console.WriteLine($"[PERSIST] inspect fault (non-fatal): {ex.Message}"); }
            }
            Thread.Sleep(any ? 50 : 400);
        }
    }

    /// <summary>
    /// Unelevated fallback for the Tasks directory: `schtasks /query /fo CSV /v /nh` via the
    /// Task Scheduler RPC service. The first poll is the baseline (pre-existing tasks are
    /// never reported); later polls diff by task name and check the "Task To Run" column.
    /// Column layout in /v mode: 1 = TaskName, 8 = Task To Run.
    /// </summary>
    private void PollTasksLoop()
    {
        Console.WriteLine("[PERSIST] Tasks dir unwatchable — using schtasks polling fallback (30 s cadence)");
        while (Volatile.Read(ref _disposed) == 0 && Volatile.Read(ref EngineState.ShuttingDown) == 0)
        {
            try { PollTasksOnce(); }
            catch (Exception ex) { Console.WriteLine($"[PERSIST] task poll fault (non-fatal): {ex.Message}"); }
            for (int i = 0; i < 150 && Volatile.Read(ref _disposed) == 0 && Volatile.Read(ref EngineState.ShuttingDown) == 0; i++)
                Thread.Sleep(200);
        }
    }

    private void PollTasksOnce()
    {
        string exe = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "schtasks.exe");
        if (!File.Exists(exe)) return;

        var psi = new System.Diagnostics.ProcessStartInfo(exe, "/query /fo CSV /v /nh")
        {
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true
        };
        var names = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        using var p = System.Diagnostics.Process.Start(psi);
        if (p == null) return;
        string output = p.StandardOutput.ReadToEnd();
        p.WaitForExit(10000);

        foreach (string raw in output.Split('\n'))
        {
            string line = raw.Trim();
            if (line.Length < 3 || line[0] != '"') continue;
            var f = SplitCsv(line);
            if (f.Count < 9) continue;
            string name = f[1];
            string toRun = f[8];
            if (name.Length == 0) continue;
            names.Add(name);

            if (_taskBaseline == null || _taskBaseline.Contains(name)) continue;
            if (Volatile.Read(ref EngineState.BypassMode) != 0) continue;
            if (!RiskyPayload(toRun)) continue;

            long now = Environment.TickCount64;
            lock (_reported)
            {
                string key = "task://" + name;
                if (_reported.TryGetValue(key, out long last) && now - last < ReportCooldownMs) continue;
                _reported[key] = now;
            }
            TotalFindings++;
            EventBus.Detection("persistence", "shield", "Scheduled task with suspicious payload",
                $"Task '{name}' -> {Trim(toRun)}", 0);
            Console.WriteLine($"[PERSIST] task '{name}' payload: {Trim(toRun)}");
        }
        _taskBaseline = names;
    }

    private static List<string> SplitCsv(string line)
    {
        var fields = new List<string>();
        var sb = new StringBuilder();
        bool inQ = false;
        for (int i = 0; i < line.Length; i++)
        {
            char c = line[i];
            if (inQ)
            {
                if (c == '"')
                {
                    if (i + 1 < line.Length && line[i + 1] == '"') { sb.Append('"'); i++; }
                    else inQ = false;
                }
                else sb.Append(c);
            }
            else if (c == '"') inQ = true;
            else if (c == ',') { fields.Add(sb.ToString()); sb.Clear(); }
            else sb.Append(c);
        }
        fields.Add(sb.ToString());
        return fields;
    }

    private void Inspect(string path, string kind)
    {
        if (Volatile.Read(ref EngineState.BypassMode) != 0) return;
        if (string.IsNullOrEmpty(path)) return;

        // The watcher fires on the first byte; the task service rewrites the file while
        // finalizing it. Let it settle before reading.
        Thread.Sleep(300);

        long now = Environment.TickCount64;
        lock (_reported)
        {
            if (_reported.TryGetValue(path, out long last) && now - last < ReportCooldownMs) return;
            if (_reported.Count > 4096) _reported.Clear();
            _reported[path] = now;
        }

        string name = Path.GetFileName(path);

        if (kind == "task")
        {
            string xml;
            try { xml = File.ReadAllText(path); }
            catch { return; } // unreadable/being-written: nothing to honestly report
            string cmd = ExtractTag(xml, "Command");
            string args = ExtractTag(xml, "Arguments");
            if (cmd.Length == 0) return;
            string payload = cmd + " " + args;
            if (!RiskyPayload(payload)) return;

            TotalFindings++;
            EventBus.Detection("persistence", "shield", "Scheduled task with suspicious payload",
                $"Task '{name}' -> {Trim(payload)}", 0);
            Console.WriteLine($"[PERSIST] task '{name}' payload: {Trim(payload)}");
            return;
        }

        string ext = Path.GetExtension(name).ToLowerInvariant();
        switch (ext)
        {
            case ".exe": case ".scr": case ".com": case ".pif": case ".bat": case ".cmd":
            case ".js": case ".jse": case ".vbs": case ".vbe": case ".wsf": case ".hta":
            case ".ps1": case ".psm1": case ".jar":
                break;
            default:
                return; // .lnk and everything else is too common in Startup to flag
        }
        TotalFindings++;
        EventBus.Detection("persistence", "shield", "Startup folder entry created",
            $"{name} in {Path.GetDirectoryName(path)}", 0);
        Console.WriteLine($"[PERSIST] startup '{name}' path: {path}");
    }

    private static string ExtractTag(string xml, string tag)
    {
        int i = xml.IndexOf("<" + tag + ">", StringComparison.OrdinalIgnoreCase);
        if (i < 0) return "";
        i += tag.Length + 2;
        int j = xml.IndexOf('<', i);
        return j < 0 ? "" : xml.Substring(i, j - i);
    }

    private static bool RiskyPayload(string s)
    {
        string l = s.ToLowerInvariant();
        if (l.Contains("\\temp\\") || l.Contains("%temp%") || l.Contains("%tmp%") ||
            l.Contains("\\downloads\\") || l.Contains("\\users\\public\\")) return true;
        if (l.Contains("powershell") && (l.Contains("-enc") || l.Contains("hidden") || l.Contains("bypass"))) return true;
        if (l.Contains("mshta") || l.Contains("wscript") || l.Contains("cscript") ||
            l.Contains("rundll32") || l.Contains("regsvr32")) return true;
        if (l.Contains("certutil") || l.Contains("bitsadmin") || l.Contains("curl")) return true;
        if (l.Contains("%comspec%") && l.Contains("/c")) return true;
        return false;
    }

    private static string Trim(string s) => s.Length > 600 ? s.Substring(0, 600) : s;

    public void Dispose()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0) return;
        foreach (var w in _watchers)
        {
            try { w.EnableRaisingEvents = false; w.Dispose(); } catch { }
        }
        try { _thread?.Join(200); } catch { }
        try { _pollThread?.Join(200); } catch { }
    }
}
