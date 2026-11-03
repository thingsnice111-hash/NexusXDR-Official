using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;

namespace NexusAV.Engine;

/// <summary>
/// User-configurable whitelist for file paths and directories.
/// Whitelisted paths are skipped by RealtimeScanner and ZeroDayEngine.
/// Persisted at %ProgramData%\NexusXDR\whitelist.json.
/// </summary>
public sealed class WhitelistManager
{
    private readonly string _filePath;
    private readonly object _lock = new();
    private WhitelistData _data = new();

    public sealed class WhitelistEntry
    {
        public string Path { get; set; } = "";
        public string AddedBy { get; set; } = "user";
        public DateTime AddedAt { get; set; } = DateTime.UtcNow;
        public string Note { get; set; } = "";
    }

    public sealed class WhitelistData
    {
        public List<WhitelistEntry> Entries { get; set; } = new();
    }

    public WhitelistManager()
    {
        string dir = NexusDataDir.Ensure();
        _filePath = Path.Combine(dir, "whitelist.json");
        Load();
    }

    private void Load()
    {
        try
        {
            if (!File.Exists(_filePath)) return;
            using var doc = JsonDocument.Parse(File.ReadAllText(_filePath));
            if (!doc.RootElement.TryGetProperty("entries", out var entries) &&
                !doc.RootElement.TryGetProperty("Entries", out entries)) return;
            if (entries.ValueKind != JsonValueKind.Array) return;

            var loaded = new List<WhitelistEntry>();
            foreach (var el in entries.EnumerateArray())
            {
                string p = GetStr(el, "path", "Path");
                if (string.IsNullOrWhiteSpace(p)) continue;
                string by = GetStr(el, "addedBy", "AddedBy");
                loaded.Add(new WhitelistEntry
                {
                    Path = p,
                    AddedBy = by.Length > 0 ? by : "user",
                    Note = GetStr(el, "note", "Note"),
                    AddedAt = DateTime.TryParse(GetStr(el, "addedAt", "AddedAt"), out var at) ? at : DateTime.UtcNow
                });
            }
            _data.Entries = loaded;
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[WHITELIST] Could not load: {ex.Message}");
        }
    }

    private static string GetStr(JsonElement el, string name, string altName)
    {
        if (el.ValueKind != JsonValueKind.Object) return "";
        if (!el.TryGetProperty(name, out var v) && !el.TryGetProperty(altName, out v)) return "";
        return v.ValueKind == JsonValueKind.String ? (v.GetString() ?? "") : "";
    }

    // Hand-rolled because the engine ships as native AOT, where reflection-based
    // JsonSerializer is disabled at runtime.
    private void Save()
    {
        try
        {
            var sb = new System.Text.StringBuilder();
            sb.Append("{\n  \"entries\": [\n");
            for (int i = 0; i < _data.Entries.Count; i++)
            {
                var e = _data.Entries[i];
                sb.Append("    { \"path\": ").Append(J.Str(e.Path))
                  .Append(", \"addedBy\": ").Append(J.Str(e.AddedBy))
                  .Append(", \"addedAt\": ").Append(J.Str(e.AddedAt.ToString("O")))
                  .Append(", \"note\": ").Append(J.Str(e.Note)).Append(" }");
                if (i < _data.Entries.Count - 1) sb.Append(',');
                sb.Append('\n');
            }
            sb.Append("  ]\n}\n");
            string tmp = _filePath + ".tmp";
            File.WriteAllText(tmp, sb.ToString());
            File.Move(tmp, _filePath, overwrite: true);
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[WHITELIST] Could not save: {ex.Message}");
        }
    }

    public void Add(string path, string addedBy = "user", string note = "")
    {
        if (string.IsNullOrWhiteSpace(path)) return;

        lock (_lock)
        {
            if (_data.Entries.Any(e => e.Path.Equals(path, StringComparison.OrdinalIgnoreCase)))
                return;

            _data.Entries.Add(new WhitelistEntry
            {
                Path = path,
                AddedBy = addedBy,
                AddedAt = DateTime.UtcNow,
                Note = note
            });
            Save();
            Console.WriteLine($"[WHITELIST] Added: {path}");
        }
    }

    public void Remove(string path)
    {
        lock (_lock)
        {
            int removed = _data.Entries.RemoveAll(e => e.Path.Equals(path, StringComparison.OrdinalIgnoreCase));
            if (removed > 0)
            {
                Save();
                Console.WriteLine($"[WHITELIST] Removed: {path}");
            }
        }
    }

    public IReadOnlyList<WhitelistEntry> GetAll()
    {
        lock (_lock)
        {
            return _data.Entries.ToList();
        }
    }

    /// <summary>
    /// Check if a path is whitelisted. Matches exact paths and parent directories.
    /// </summary>
    public bool IsWhitelisted(string path)
    {
        if (string.IsNullOrWhiteSpace(path)) return false;

        lock (_lock)
        {
            foreach (var entry in _data.Entries)
            {
                // Exact match
                if (path.Equals(entry.Path, StringComparison.OrdinalIgnoreCase))
                    return true;

                // Parent directory match
                if (path.StartsWith(entry.Path + "\\", StringComparison.OrdinalIgnoreCase) ||
                    path.StartsWith(entry.Path + "/", StringComparison.OrdinalIgnoreCase))
                    return true;
            }
        }

        return false;
    }

    public int Count
    {
        get
        {
            lock (_lock)
            {
                return _data.Entries.Count;
            }
        }
    }
}
