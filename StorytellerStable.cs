using System;
using System.Collections.Generic;
using System.Globalization;
using System.Text;

namespace NexusAV.Engine;

/// <summary>
/// The storyline engine: turns raw detection signals into an ordered, human-readable
/// account of "what happened, how, and in what chain" — the SentinelOne-style attack
/// story. Every episode is recorded from a real engine signal (ETW cross-process call,
/// graph edge, DCA verdict, guardian hit, detection, quarantine, SAS flag, device event);
/// nothing is synthesized and empty stories stay empty.
///
/// Episodes stream to the GUI as incremental <c>NEXUS_EVENT {"t":"story",...}</c> records;
/// on demand (<c>story_get</c>) a full snapshot with a narrative is replayed.
/// </summary>
public sealed class StorytellerStable
{
    private const int MaxEpisodes = 600;
    private const int MaxNarrativeLines = 120;

    public sealed record Episode(
        long Seq, long TsMs, string Kind, string Severity,
        uint Pid, uint ParentPid, string Image, string Title, string Detail);

    private readonly Storyteller _story;
    private readonly List<Episode> _episodes = new();
    private readonly object _lock = new();
    private readonly HashSet<uint> _processEpisodes = new();
    private long _seq;

    public StorytellerStable(Storyteller story)
    {
        _story = story;
    }

    public int EpisodeCount { get { lock (_lock) return _episodes.Count; } }

    // ── Recording (one call per real engine signal) ─────────────────────────

    /// <summary>
    /// Process-start episode, recorded only when the start is actually part of a
    /// flagged or risky chain (parent already scored, child scored, risky spawner
    /// image, or a guarded interpreter). Plain signed spawns stay out of the story.
    /// </summary>
    public void AddProcessStart(uint pid, uint parentPid, string image)
    {
        try
        {
            if (pid <= 4 || image.Length == 0) return;
            int childConf = 0, parentConf = 0;
            string parentImage = "";
            bool parentRisky = false;
            if (_story.Processes.TryGetValue(pid, out var child)) childConf = child.Confidence;
            if (parentPid != 0 && _story.Processes.TryGetValue(parentPid, out var parent))
            {
                parentConf = parent.Confidence;
                parentImage = parent.ImageName;
                parentRisky = RiskySpawners.Contains(parent.ImageName);
            }
            bool guarded = ActiveGuardian.IsGuardedImageName(image);
            bool interesting = childConf >= 30 || parentConf >= 30 || parentRisky || (guarded && parentConf >= 10);
            if (!interesting) return;

            lock (_lock)
            {
                if (!_processEpisodes.Add(pid)) return;
                if (_processEpisodes.Count > 4096) _processEpisodes.Clear();
            }

            string chain = parentImage.Length > 0 ? $"{parentImage} (pid {parentPid})" : $"pid {parentPid}";
            Record("proc", "notice", pid, parentPid, image,
                $"Process started: {image} (pid {pid})",
                $"{chain} spawned {image}" +
                (parentConf >= 30 ? $" — parent confidence {parentConf}" : "") +
                (childConf >= 30 ? $" — child confidence {childConf}" : "") +
                (parentRisky ? $" — document/office parent ({parentImage})" : ""));
        }
        catch { }
    }

    public void AddEdge(uint src, uint dst, string type, int weight, string extra)
    {
        try
        {
            if (type == nameof(EdgeType.Tree) || weight <= 0) return;
            string srcImg = ImageOf(src), dstImg = dst != 0 && dst != uint.MaxValue ? ImageOf(dst) : "";
            string sev = type is nameof(EdgeType.ThreadInject) or nameof(EdgeType.RwxInject) or nameof(EdgeType.PpidSpoof)
                ? (weight >= 30 ? "high" : "medium") : "medium";
            string title = type switch
            {
                nameof(EdgeType.ThreadInject) => $"Remote thread injection: {srcImg} -> {dstImg}",
                nameof(EdgeType.RwxInject) => $"Cross-process memory operation: {srcImg} -> {dstImg}",
                nameof(EdgeType.PpidSpoof) => $"Parent-PID spoofing suspected on {srcImg}",
                nameof(EdgeType.DnsQuery) => $"Suspicious DNS/network activity from {srcImg}",
                nameof(EdgeType.ShieldAction) => $"Behavior signal on {srcImg} (confidence +{weight})",
                _ => $"{type}: {srcImg} -> {dstImg}"
            };
            Record("edge", sev, src, dst, srcImg, title,
                $"edge={type} weight={weight}" + (extra.Length > 0 ? $" :: {extra}" : ""));
        }
        catch { }
    }

    public void AddAlert(uint pid, string image, int conf, string severity, string detail)
    {
        try
        {
            string sev = severity switch
            {
                "shield" => "critical",
                "veto" => "medium",
                "audit" => "medium",
                _ => "high"
            };
            Record("alert", sev, pid, 0, image,
                severity == "shield" ? $"Shield engaged on {image}" : $"{severity.ToUpperInvariant()}: {image} (confidence {conf})",
                detail);
        }
        catch { }
    }

    public void AddGuard(uint pid, string image, string ruleId, string technique, string severity, string action, string path, int score)
    {
        try
        {
            string sev = severity == "high" ? "high" : "medium";
            string what = action switch
            {
                "terminated" => "terminated",
                "flagged" => "flagged for review",
                "allowlisted" => "allowlisted (not acted on)",
                _ => action
            };
            Record("guard", sev, pid, 0, image,
                $"Guardian {what}: {image} (pid {pid}) — {ruleId}",
                $"{technique} [{ruleId}] :: {path}" + (score > 0 ? $" — confidence {score}" : ""));
        }
        catch { }
    }

    public void AddDetection(string category, string severity, string title, string detail, uint pid)
    {
        try
        {
            string img = pid != 0 ? ImageOf(pid) : "";
            Record("detect", NormSev(severity), pid, 0, img, $"[{category}] {title}", detail);
        }
        catch { }
    }

    public void AddQuarantine(string originalPath, string threat, string action)
    {
        try
        {
            if (action == "list") return; // listing the vault is not a story event
            string name = originalPath;
            int slash = name.LastIndexOfAny(new[] { '\\', '/' });
            if (slash >= 0) name = name.Substring(slash + 1);
            Record("quar", action == "quarantined" ? "high" : "notice", 0, 0, "",
                action == "quarantined" ? $"Quarantined: {name}" : $"Quarantine {action}: {name}",
                $"{threat} :: {originalPath}");
        }
        catch { }
    }

    public void AddMemory(uint pid, string image, string reason)
    {
        try
        {
            Record("mem", "high", pid, 0, image,
                $"Memory integrity anomaly: {image} (pid {pid})", reason);
        }
        catch { }
    }

    /// <summary>Analyst-initiated response from the console (kill / network containment).</summary>
    public void AddMitigation(string verb, uint pid, string image, string detail)
    {
        try
        {
            Record("mitig", "high", pid, 0, image,
                $"Analyst response: {verb} {image} (pid {pid})", detail);
        }
        catch { }
    }

    public void AddUsbDevice(string op, string deviceInstance, string state, string message)
    {
        try
        {
            string sev = op == "blocked" ? "high" : "notice";
            Record("usb", sev, 0, 0, "",
                $"USB device {op}: {deviceInstance}", $"{state} — {message}");
        }
        catch { }
    }

    public void AddFirmware(string summary, int findings)
    {
        try
        {
            Record("fw", findings > 0 ? "high" : "notice", 0, 0, "",
                $"Firmware attestation: {summary}", $"findings={findings}");
        }
        catch { }
    }

    // ── Publishing ──────────────────────────────────────────────────────────

    private void Record(string kind, string severity, uint pid, uint parentPid, string image, string title, string detail)
    {
        string json;
        long seq;
        lock (_lock)
        {
            seq = ++_seq;
            var ep = new Episode(seq, DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(), kind, severity,
                pid, parentPid, image, title, Trim(detail));
            _episodes.Add(ep);
            if (_episodes.Count > MaxEpisodes) _episodes.RemoveRange(0, _episodes.Count - MaxEpisodes);
            json = BuildEpisodeJson(ep, "ep");
        }
        EventBus.Publish(json);
    }

    /// <summary>Full story snapshot: episodes + live process nodes + a derived narrative.</summary>
    public void PublishSnapshot()
    {
        string json;
        lock (_lock)
        {
            var sb = new StringBuilder(16 * 1024);
            sb.Append("{\"t\":\"story\",\"op\":\"snap\",\"count\":").Append(_episodes.Count).Append(",\"eps\":[");
            for (int i = 0; i < _episodes.Count; i++)
            {
                if (i > 0) sb.Append(',');
                BuildEpisodeJsonInto(sb, _episodes[i]);
            }
            sb.Append("],\"narrative\":[");
            int start = Math.Max(0, _episodes.Count - MaxNarrativeLines);
            bool first = true;
            for (int i = start; i < _episodes.Count; i++)
            {
                string line = Narrate(_episodes[i]);
                if (line.Length == 0) continue;
                if (!first) sb.Append(',');
                first = false;
                sb.Append('"').Append(JEscape(line)).Append('"');
            }
            sb.Append("]}");
            json = sb.ToString();
        }
        EventBus.Publish(json);
    }

    private static string BuildEpisodeJson(Episode e, string op)
    {
        // Incremental record: GUI's ParseEpisode reads the fields at TOP level, so the
        // episode fields are flattened into the story object (not nested under a key).
        var sb = new StringBuilder(256);
        sb.Append("{\"t\":\"story\",\"op\":\"").Append(op).Append("\",");
        AppendEpisodeFields(sb, e);
        sb.Append('}');
        return sb.ToString();
    }

    private static void BuildEpisodeJsonInto(StringBuilder sb, Episode e)
    {
        sb.Append('{');
        AppendEpisodeFields(sb, e);
        sb.Append('}');
    }

    private static void AppendEpisodeFields(StringBuilder sb, Episode e)
    {
        sb.Append("\"seq\":").Append(e.Seq)
          .Append(",\"ts\":").Append(e.TsMs)
          .Append(",\"k\":").Append(J.Str(e.Kind))
          .Append(",\"sev\":").Append(J.Str(e.Severity))
          .Append(",\"pid\":").Append(e.Pid)
          .Append(",\"ppid\":").Append(e.ParentPid)
          .Append(",\"img\":").Append(J.Str(e.Image))
          .Append(",\"title\":").Append(J.Str(e.Title))
          .Append(",\"detail\":").Append(J.Str(e.Detail));
    }

    /// <summary>One real sentence per episode for the "how this happened" list.</summary>
    private static string Narrate(Episode e)
    {
        string t = DateTimeOffset.FromUnixTimeMilliseconds(e.TsMs).ToLocalTime().ToString("HH:mm:ss", CultureInfo.InvariantCulture);
        string img = e.Image.Length > 0 ? e.Image : "unknown";
        return e.Kind switch
        {
            "proc" => $"[{t}] {e.Detail}",
            "edge" => $"[{t}] {e.Title} ({e.Detail})",
            "alert" => $"[{t}] {e.Title} — {e.Detail}",
            "guard" => $"[{t}] Command-line guard: {e.Detail}",
            "detect" => $"[{t}] Detection: {e.Title} — {e.Detail}",
            "quar" => $"[{t}] {e.Title} — {e.Detail}",
            "mem" => $"[{t}] Memory integrity: {img} — {e.Detail}",
            "mitig" => $"[{t}] Analyst response: {e.Detail}",
            "usb" => $"[{t}] {e.Title} — {e.Detail}",
            "fw" => $"[{t}] {e.Title} — {e.Detail}",
            _ => $"[{t}] {e.Title}"
        };
    }

    private string ImageOf(uint pid)
    {
        if (pid == 0) return "";
        return _story.Processes.TryGetValue(pid, out var n) ? n.ImageName : $"pid{pid}";
    }

    private static string NormSev(string s) => s switch
    {
        "critical" => "critical",
        "high" or "shield" => "high",
        "medium" or "audit" => "medium",
        "low" => "notice",
        _ => "notice"
    };

    private static string Trim(string s)
    {
        if (s.Length <= 400) return s;
        return s.Substring(0, 400);
    }

    private static string JEscape(string s)
    {
        // J.Str already escapes for JSON; strip the surrounding quotes here.
        string q = J.Str(s);
        return q.Length >= 2 ? q.Substring(1, q.Length - 2) : q;
    }

    private static readonly HashSet<string> RiskySpawners = new(StringComparer.OrdinalIgnoreCase)
    {
        "winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "msaccess.exe",
        "mspub.exe", "onenote.exe", "wscript.exe", "cscript.exe", "mshta.exe",
        "hh.exe", "forfiles.exe", "wmiprvse.exe"
    };
}
