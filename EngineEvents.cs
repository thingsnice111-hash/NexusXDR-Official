using System;
using System.Collections.Generic;
using System.Globalization;
using System.Text;
using System.Text.Json;
using System.Threading;

namespace NexusAV.Engine;

/// <summary>
/// Real-time, AOT-safe event bus. The engine publishes machine-readable events
/// (processes, graph edges, detections, quarantine, scans, TPM attestation) as
/// single-line <c>NEXUS_EVENT {json}</c> records on stdout. The GUI console parses
/// only these tagged lines and binds them to the live dashboard + notifications.
/// JSON is hand-serialized (no reflection) so it stays Native-AOT compatible.
/// </summary>
public static class EventBus
{
    public const string EventPrefix = "NEXUS_EVENT ";
    public const string CommandPrefix = "NEXUS_CMD ";

    /// <summary>
    /// Storyline sink: every typed Detection/Alert/Guard/Quarantine event also becomes a
    /// StorytellerStable episode ("what happened, how, in what chain"). Set once at engine
    /// startup; stays null in contexts without a storyline.
    /// </summary>
    public static StorytellerStable? StoryFeed;

    private static readonly object _writeLock = new();
    private static long _seq;

    /// <summary>Emit a raw pre-built JSON object as a tagged event line on stdout.</summary>
    public static void Publish(string json)
    {
        // The engine is a child process of the GUI. If the GUI closes, detaches, or
        // stops draining our stdout, the pipe breaks and Console.Out throws IOException.
        // That exception used to propagate on whatever thread emitted the event (guardian,
        // ETW callback, ring consumer) and terminate the whole process. Swallow it here and
        // ask every worker loop to wind down instead, so a dead GUI can never crash the engine.
        try
        {
            lock (_writeLock)
            {
                Console.Out.Write(EventPrefix);
                Console.Out.WriteLine(json);
                Console.Out.Flush();
            }
        }
        catch (System.IO.IOException)
        {
            Volatile.Write(ref EngineState.ShuttingDown, 1);
        }
        catch (ObjectDisposedException)
        {
            Volatile.Write(ref EngineState.ShuttingDown, 1);
        }
    }

    private static long NextSeq() => Interlocked.Increment(ref _seq);

    // ── Typed emit helpers ────────────────────────────────────────────────

    public static void Status(string text) =>
        Publish($"{{\"t\":\"status\",\"seq\":{NextSeq()},\"s\":{J.Str(text)}}}");

    public static void Process(uint pid, uint ppid, string image, int confidence, bool allowlisted, string sigState) =>
        Publish($"{{\"t\":\"proc\",\"seq\":{NextSeq()},\"pid\":{pid},\"ppid\":{ppid},\"img\":{J.Str(image)}," +
                $"\"conf\":{confidence},\"allow\":{(allowlisted ? "true" : "false")},\"sig\":{J.Str(sigState)},\"ts\":{J.Str(Now())}}}");

    public static void Edge(uint src, uint dst, string type, int weight, DateTimeOffset ts, string extra) =>
        Publish($"{{\"t\":\"edge\",\"seq\":{NextSeq()},\"src\":{src},\"dst\":{dst},\"et\":{J.Str(type)}," +
                $"\"w\":{weight},\"ts\":{J.Str(ts.ToUniversalTime().ToString("o", CultureInfo.InvariantCulture))},\"x\":{J.Str(extra)}}}");

    public static void Alert(uint pid, string image, int confidence, string severity, string action)
    {
        Publish($"{{\"t\":\"alert\",\"seq\":{NextSeq()},\"pid\":{pid},\"img\":{J.Str(image)},\"conf\":{confidence}," +
                $"\"sev\":{J.Str(severity)},\"action\":{J.Str(action)},\"ts\":{J.Str(Now())}}}");
        StoryFeed?.AddAlert(pid, image, confidence, severity, action);
    }

    public static void Detection(string category, string severity, string title, string detail, uint pid)
    {
        Publish($"{{\"t\":\"detect\",\"seq\":{NextSeq()},\"cat\":{J.Str(category)},\"sev\":{J.Str(severity)}," +
                $"\"title\":{J.Str(title)},\"detail\":{J.Str(detail)},\"pid\":{pid},\"ts\":{J.Str(Now())}}}");
        StoryFeed?.AddDetection(category, severity, title, detail, pid);
    }

    public static void Quarantine(string quarantinePath, string originalPath, string action, string threat, string sha)
    {
        Publish($"{{\"t\":\"quar\",\"seq\":{NextSeq()},\"qpath\":{J.Str(quarantinePath)},\"opath\":{J.Str(originalPath)}," +
                $"\"action\":{J.Str(action)},\"threat\":{J.Str(threat)},\"sha\":{J.Str(sha)},\"ts\":{J.Str(Now())}}}");
        StoryFeed?.AddQuarantine(originalPath.Length > 0 ? originalPath : quarantinePath, threat, action);
    }

    public static void Scan(string path, int malicious, int total, string detectionNames, bool isMalicious, string error) =>
        Publish($"{{\"t\":\"scan\",\"seq\":{NextSeq()},\"path\":{J.Str(path)},\"mal\":{malicious},\"total\":{total}," +
                $"\"names\":{J.Str(detectionNames)},\"bad\":{(isMalicious ? "true" : "false")},\"err\":{J.Str(error)},\"ts\":{J.Str(Now())}}}");

    public static void Tpm(string summary, string secureBoot, string uefi, bool tamper, bool tpmPresent, bool tcgParsed, int findings) =>
        Publish($"{{\"t\":\"tpm\",\"seq\":{NextSeq()},\"summary\":{J.Str(summary)},\"sb\":{J.Str(secureBoot)}," +
                $"\"uefi\":{J.Str(uefi)},\"tamper\":{(tamper ? "true" : "false")},\"tpm\":{(tpmPresent ? "true" : "false")}," +
                $"\"tcg\":{(tcgParsed ? "true" : "false")},\"findings\":{findings},\"ts\":{J.Str(Now())}}}");

    public static void VtStatus(bool ok, string status) =>
        Publish($"{{\"t\":\"vt\",\"seq\":{NextSeq()},\"ok\":{(ok ? "true" : "false")},\"status\":{J.Str(status)},\"ts\":{J.Str(Now())}}}");

    public static void Guard(uint pid, uint parentPid, string image, string commandLine, string ruleId,
        string technique, string severity, string action, string filePath, int confidence)
    {
        Publish($"{{\"t\":\"guard\",\"seq\":{NextSeq()},\"pid\":{pid},\"ppid\":{parentPid},\"img\":{J.Str(image)}," +
                $"\"cmd\":{J.Str(commandLine)},\"rule\":{J.Str(ruleId)},\"tech\":{J.Str(technique)},\"sev\":{J.Str(severity)}," +
                $"\"action\":{J.Str(action)},\"path\":{J.Str(filePath)},\"conf\":{confidence},\"ts\":{J.Str(Now())}}}");
        StoryFeed?.AddGuard(pid, image, ruleId, technique, severity, action, filePath, confidence);
    }

    public static void Stats(int events, int anomalies, int shields) =>
        Publish($"{{\"t\":\"stats\",\"seq\":{NextSeq()},\"events\":{events},\"anomalies\":{anomalies},\"shields\":{shields}}}");

    /// <summary>A Mystral sensor finding relayed through the bridge (source-tagged, engine stays the actor).</summary>
    public static void MystralFinding(uint pid, string image, string kind, string severity, string detail) =>
        Publish($"{{\"t\":\"mystral_finding\",\"seq\":{NextSeq()},\"src\":\"mystral\",\"pid\":{pid},\"img\":{J.Str(image)}," +
                $"\"kind\":{J.Str(kind)},\"sev\":{J.Str(severity)},\"detail\":{J.Str(detail)},\"ts\":{J.Str(Now())}}}");

    /// <summary>A process start observed by the Mystral sensor (companion feed, source-tagged).</summary>
    public static void MystralProc(uint pid, uint ppid, string image, string cmd, bool onDisk) =>
        Publish($"{{\"t\":\"mystral_proc\",\"seq\":{NextSeq()},\"src\":\"mystral\",\"pid\":{pid},\"ppid\":{ppid}," +
                $"\"img\":{J.Str(image)},\"cmd\":{J.Str(cmd)},\"ondisk\":{(onDisk ? "true" : "false")},\"ts\":{J.Str(Now())}}}");

    /// <summary>Mystral sensor attach/detach state as seen by the engine's bridge server.</summary>
    public static void MystralStatus(bool connected) =>
        Publish($"{{\"t\":\"mystral_status\",\"seq\":{NextSeq()},\"src\":\"mystral\",\"connected\":{(connected ? "true" : "false")},\"ts\":{J.Str(Now())}}}");

    /// <summary>What the engine actually enforced on its own process, verified by reading the policies back.</summary>
    public static void HardenStatus(bool acgRequested, bool acgActive, string acgSource, string detail) =>
        Publish($"{{\"t\":\"harden_status\",\"seq\":{NextSeq()},\"requested\":{(acgRequested ? "true" : "false")}," +
                $"\"acg\":{(acgActive ? "true" : "false")},\"acg_src\":{J.Str(acgSource)},\"detail\":{J.Str(detail)},\"ts\":{J.Str(Now())}}}");

    /// <summary>Live mitigation policy set of one process, read with GetProcessMitigationPolicy (no injection).</summary>
    public static void MitigationRow(uint pid, string image, string policies, string error) =>
        Publish($"{{\"t\":\"mitigation_row\",\"seq\":{NextSeq()},\"pid\":{pid},\"img\":{J.Str(image)}," +
                $"\"pol\":{J.Str(policies)},\"err\":{J.Str(error)},\"ts\":{J.Str(Now())}}}");

    public static void MitigationDone(int rows, string note) =>
        Publish($"{{\"t\":\"mitigation_done\",\"seq\":{NextSeq()},\"rows\":{rows},\"note\":{J.Str(note)},\"ts\":{J.Str(Now())}}}");

    /// <summary>One whitelist entry (path added, removed, or listed).</summary>
    public static void WhitelistEntry(string path, string action, string note) =>
        Publish($"{{\"t\":\"whitelist_entry\",\"seq\":{NextSeq()},\"path\":{J.Str(path)},\"action\":{J.Str(action)},\"note\":{J.Str(note)},\"ts\":{J.Str(Now())}}}");

    public static void WhitelistDone(int count) =>
        Publish($"{{\"t\":\"whitelist_done\",\"seq\":{NextSeq()},\"count\":{count},\"ts\":{J.Str(Now())}}}");

    /// <summary>One known-bad fingerprint row (action: added / removed / list / match).</summary>
    public static void FpEntry(string action, string sha256, string importHash, string source, string note, string path) =>
        Publish($"{{\"t\":\"fp_entry\",\"seq\":{NextSeq()},\"action\":{J.Str(action)},\"sha\":{J.Str(sha256)},\"imp\":{J.Str(importHash)},\"src\":{J.Str(source)},\"note\":{J.Str(note)},\"path\":{J.Str(path)},\"ts\":{J.Str(Now())}}}");

    public static void FpDone(int count) =>
        Publish($"{{\"t\":\"fp_done\",\"seq\":{NextSeq()},\"count\":{count},\"ts\":{J.Str(Now())}}}");

    private static string Now() => DateTimeOffset.UtcNow.ToUnixTimeMilliseconds().ToString(CultureInfo.InvariantCulture);
}

/// <summary>Minimal manual JSON primitives (AOT-safe, escaping only).</summary>
internal static class J
{
    public static string Str(string? s)
    {
        if (string.IsNullOrEmpty(s)) return "\"\"";
        var sb = new StringBuilder(s.Length + 2);
        sb.Append('"');
        foreach (char c in s)
        {
            switch (c)
            {
                case '"': sb.Append("\\\""); break;
                case '\\': sb.Append("\\\\"); break;
                case '\n': sb.Append("\\n"); break;
                case '\r': sb.Append("\\r"); break;
                case '\t': sb.Append("\\t"); break;
                default:
                    if (c < 0x20) sb.Append("\\u").Append(((int)c).ToString("x4"));
                    else sb.Append(c);
                    break;
            }
        }
        sb.Append('"');
        return sb.ToString();
    }
}

/// <summary>
/// Reads <c>NEXUS_CMD {json}</c> lines from stdin and raises <see cref="OnCommand"/>.
/// Parsing uses the System.Text.Json DOM (reflection-free / AOT-safe).
/// </summary>
public sealed class CommandReader : IDisposable
{
    public sealed record Command(string Name, IReadOnlyDictionary<string, string> Fields);

    public event Action<Command>? OnCommand;

    private readonly Thread _thread;
    private volatile bool _running = true;

    public CommandReader()
    {
        _thread = new Thread(Loop) { IsBackground = true, Name = "Nexus-CommandReader" };
    }

    public void Start() => _thread.Start();

    private void Loop()
    {
        try
        {
            while (_running)
            {
                string? line = Console.In.ReadLine();
                if (line == null) break; // stdin closed (parent exited)
                int idx = line.IndexOf(EventBus.CommandPrefix, StringComparison.Ordinal);
                if (idx < 0) continue;
                string json = line.Substring(idx + EventBus.CommandPrefix.Length).Trim();
                Command? cmd = Parse(json);
                if (cmd != null) OnCommand?.Invoke(cmd);
            }
        }
        catch
        {
            // stdin errors just stop the reader
        }
    }

    private static Command? Parse(string json)
    {
        try
        {
            using var doc = JsonDocument.Parse(json);
            var root = doc.RootElement;
            if (!root.TryGetProperty("c", out var cEl)) return null;
            string name = cEl.GetString() ?? "";
            var fields = new Dictionary<string, string>(StringComparer.Ordinal);
            foreach (var p in root.EnumerateObject())
            {
                if (p.Name == "c") continue;
                fields[p.Name] = p.Value.ValueKind == JsonValueKind.String
                    ? (p.Value.GetString() ?? "")
                    : p.Value.ToString();
            }
            return new Command(name, fields);
        }
        catch
        {
            return null;
        }
    }

    public void Dispose() => _running = false;
}
