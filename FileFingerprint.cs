using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace NexusAV.Engine;

/// <summary>
/// One known-bad file identity: exact hash plus structure-derived hashes that survive
/// renaming, repackaging of the overlay and trivial rebuilds.
/// </summary>
public sealed class FingerprintEntry
{
    public string Sha256 { get; set; } = "";
    public string ImportHash { get; set; } = "";
    public string SectionHashes { get; set; } = "";
    public string Fuzzy { get; set; } = "";
    public long Size { get; set; }
    public string Source { get; set; } = "";
    public string Note { get; set; } = "";
    public string Path { get; set; } = "";
    public DateTime RecordedAt { get; set; } = DateTime.UtcNow;
}

/// <summary>
/// Persistent store of known-bad fingerprints at %ProgramData%\NexusXDR\fingerprints.json.
/// Read/write only from the engine; the GUI manages it through fp_* commands.
/// </summary>
public sealed class FingerprintStore
{
    public const int MaxEntries = 2000;

    private readonly string _filePath;
    private readonly object _lock = new();
    private readonly List<FingerprintEntry> _entries = new();

    public int ExactMatches;
    public int SameCodeMatches;
    public int FuzzyMatches;

    public FingerprintStore()
    {
        string dir = NexusDataDir.Ensure();
        _filePath = Path.Combine(dir, "fingerprints.json");
        Load();
    }

    public string FilePath => _filePath;

    public int Count { get { lock (_lock) return _entries.Count; } }

    public bool Add(FingerprintEntry entry)
    {
        if (string.IsNullOrWhiteSpace(entry.Sha256)) return false;
        lock (_lock)
        {
            if (_entries.Any(e => string.Equals(e.Sha256, entry.Sha256, StringComparison.OrdinalIgnoreCase)))
                return false;

            _entries.Add(entry);
            while (_entries.Count > MaxEntries) _entries.RemoveAt(0);
            Save();
        }
        return true;
    }

    public bool Remove(string sha256)
    {
        if (string.IsNullOrWhiteSpace(sha256)) return false;
        int removed;
        lock (_lock)
        {
            removed = _entries.RemoveAll(e => string.Equals(e.Sha256, sha256, StringComparison.OrdinalIgnoreCase));
            if (removed > 0) Save();
        }
        return removed > 0;
    }

    public IReadOnlyList<FingerprintEntry> GetAll()
    {
        lock (_lock) return _entries.ToList();
    }

    public readonly record struct Match(FingerprintEntry Entry, string Kind);

    /// <summary>
    /// Tiers, strongest first: identical bytes, identical code (imports + every section),
    /// then the rolling fuzzy signature. The weaker tiers are reported, never acted on alone.
    /// </summary>
    public Match? Lookup(string sha256, string importHash, string sectionHashes, string fuzzy)
    {
        lock (_lock)
        {
            foreach (var e in _entries)
            {
                if (!string.IsNullOrEmpty(sha256) &&
                    string.Equals(e.Sha256, sha256, StringComparison.OrdinalIgnoreCase))
                {
                    ExactMatches++;
                    return new Match(e, "exact");
                }
            }

            if (!string.IsNullOrEmpty(importHash) && !string.IsNullOrEmpty(sectionHashes))
            {
                foreach (var e in _entries)
                {
                    if (string.Equals(e.ImportHash, importHash, StringComparison.OrdinalIgnoreCase) &&
                        string.Equals(e.SectionHashes, sectionHashes, StringComparison.OrdinalIgnoreCase))
                    {
                        SameCodeMatches++;
                        return new Match(e, "same_code");
                    }
                }
            }

            if (!string.IsNullOrEmpty(fuzzy))
            {
                foreach (var e in _entries)
                {
                    if (string.Equals(e.Fuzzy, fuzzy, StringComparison.OrdinalIgnoreCase))
                    {
                        FuzzyMatches++;
                        return new Match(e, "fuzzy");
                    }
                }
            }
        }
        return null;
    }

    private void Load()
    {
        try
        {
            if (!File.Exists(_filePath)) return;
            var loaded = JsonSerializer.Deserialize(File.ReadAllText(_filePath),
                FingerprintJsonContext.Default.ListFingerprintEntry);
            if (loaded == null) return;
            lock (_lock)
            {
                _entries.Clear();
                foreach (var e in loaded.Where(e => !string.IsNullOrWhiteSpace(e.Sha256)))
                    _entries.Add(e);
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[FP] Could not load fingerprints: {ex.Message}");
        }
    }

    private void Save()
    {
        try
        {
            string json = JsonSerializer.Serialize(_entries, FingerprintJsonContext.Default.ListFingerprintEntry);
            string tmp = _filePath + ".tmp";
            File.WriteAllText(tmp, json);
            File.Move(tmp, _filePath, overwrite: true);
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[FP] Could not save fingerprints: {ex.Message}");
        }
    }
}

// Source-generated serialization: reflection-based JsonSerializer is disabled under PublishAot=true.
[JsonSourceGenerationOptions(WriteIndented = true)]
[JsonSerializable(typeof(List<FingerprintEntry>))]
internal sealed partial class FingerprintJsonContext : JsonSerializerContext
{
}

/// <summary>
/// Computes the fingerprint of one file. Read-only, bounded: files above the structure cap are
/// still hashed and fuzzed by streaming, but their PE structure is not parsed.
/// </summary>
public static class FileFingerprinter
{
    public const long StructureCapBytes = 32L * 1024 * 1024;
    private const int MaxPieces = 128;

    public static FingerprintEntry? Compute(string path, string source, string note = "")
    {
        try
        {
            if (!File.Exists(path)) return null;
            var fi = new FileInfo(path);

            var entry = new FingerprintEntry
            {
                Sha256 = ToHex(BcryptSha256.HashFile(path)),
                Size = fi.Length,
                Source = source,
                Note = note,
                Path = path,
                RecordedAt = DateTime.UtcNow
            };

            if (fi.Length <= StructureCapBytes)
            {
                byte[] buf = File.ReadAllBytes(path);
                var pe = PeInfo.TryParse(buf);
                if (pe != null)
                {
                    entry.ImportHash = ImportHash(buf, pe);
                    entry.SectionHashes = SectionHashes(buf, pe);
                }
                entry.Fuzzy = Fuzzy(buf, 0, buf.Length);
            }
            else
            {
                entry.Fuzzy = FuzzyStream(path);
            }

            return entry;
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[FP] fingerprint failed for {path}: {ex.Message}");
            return null;
        }
    }

    public static string Sha256Of(string path)
    {
        try { return ToHex(BcryptSha256.HashFile(path)); }
        catch { return ""; }
    }

    private sealed class PeInfo
    {
        public bool Is64;
        public uint ImportRva;
        public int SectionCount;
        public uint[] Va = Array.Empty<uint>();
        public uint[] VSize = Array.Empty<uint>();
        public uint[] Raw = Array.Empty<uint>();
        public uint[] RawPtr = Array.Empty<uint>();
        public string[] Names = Array.Empty<string>();

        public static PeInfo? TryParse(byte[] b)
        {
            if (b.Length < 0x40 || b[0] != 'M' || b[1] != 'Z') return null;
            int pe = (int)ReadU32(b, 0x3C);
            if (pe <= 0 || pe + 24 + 2 > b.Length) return null;
            if (b[pe] != 'P' || b[pe + 1] != 'E' || b[pe + 2] != 0 || b[pe + 3] != 0) return null;

            ushort sections = ReadU16(b, pe + 6);
            ushort optSize = ReadU16(b, pe + 20);
            int opt = pe + 24;
            if (opt + 2 > b.Length) return null;
            ushort magic = ReadU16(b, opt);
            bool is64 = magic == 0x20b;
            if (magic != 0x10b && !is64) return null;

            int ddStart = opt + (is64 ? 112 : 96);
            if (ddStart + 16 > b.Length) return null;
            uint importRva = ReadU32(b, ddStart + 8);

            var info = new PeInfo { Is64 = is64, ImportRva = importRva };
            int secStart = opt + optSize;
            int n = Math.Min((int)sections, 96);
            info.Va = new uint[n]; info.VSize = new uint[n];
            info.Raw = new uint[n]; info.RawPtr = new uint[n]; info.Names = new string[n];
            int kept = 0;
            for (int i = 0; i < n; i++)
            {
                int s = secStart + i * 40;
                if (s + 40 > b.Length) break;
                info.Names[kept] = Encoding.ASCII.GetString(b, s, 8).TrimEnd('\0');
                info.VSize[kept] = ReadU32(b, s + 8);
                info.Va[kept] = ReadU32(b, s + 12);
                info.Raw[kept] = ReadU32(b, s + 16);
                info.RawPtr[kept] = ReadU32(b, s + 20);
                kept++;
            }
            info.SectionCount = kept;
            return kept > 0 ? info : null;
        }

        public int RvaToOffset(uint rva)
        {
            for (int i = 0; i < SectionCount; i++)
            {
                uint size = Raw[i] != 0 ? Raw[i] : VSize[i];
                if (rva >= Va[i] && rva < Va[i] + size)
                    return (int)(RawPtr[i] + (rva - Va[i]));
            }
            return -1;
        }
    }

    /// <summary>
    /// Simplified import hash: MD5 over "dll.function" pairs in table order. Ordinal-only imports
    /// are skipped because resolving them needs a per-DLL export table, so this is NOT
    /// wire-compatible with commercial imphash — it only has to be stable across our own builds.
    /// </summary>
    private static string ImportHash(byte[] b, PeInfo pe)
    {
        if (pe.ImportRva == 0) return "";
        int off = pe.RvaToOffset(pe.ImportRva);
        if (off < 0) return "";

        var names = new List<string>(64);
        int entrySize = pe.Is64 ? 8 : 4;
        ulong ordinalFlag = pe.Is64 ? 0x8000000000000000UL : 0x80000000u;

        for (int i = 0; i < 96; i++)
        {
            int d = off + i * 20;
            if (d + 20 > b.Length) break;
            uint ilt = ReadU32(b, d);
            uint nameRva = ReadU32(b, d + 12);
            uint iat = ReadU32(b, d + 16);
            if (ilt == 0 && nameRva == 0 && iat == 0) break;

            int nameOff = pe.RvaToOffset(nameRva);
            if (nameOff < 0) continue;
            string dll = ReadAscii(b, nameOff, 64).ToLowerInvariant();
            if (dll.Length == 0) continue;

            int t = pe.RvaToOffset(ilt != 0 ? ilt : iat);
            if (t < 0) continue;

            for (int j = 0; j < 1024; j++)
            {
                int e = t + j * entrySize;
                if (e + entrySize > b.Length) break;
                ulong val = pe.Is64 ? ReadU64(b, e) : ReadU32(b, e);
                if (val == 0) break;
                if ((val & ordinalFlag) != 0) continue;
                int hint = pe.RvaToOffset((uint)(val & 0x7FFFFFFF));
                if (hint < 0 || hint + 3 > b.Length) continue;
                string fn = ReadAscii(b, hint + 2, 128).ToLowerInvariant();
                if (fn.Length > 0) names.Add(dll + "." + fn);
            }
        }

        return names.Count == 0 ? "" : Md5Hex(string.Join(",", names));
    }

    private static string SectionHashes(byte[] b, PeInfo pe)
    {
        var parts = new List<string>(pe.SectionCount);
        for (int i = 0; i < pe.SectionCount; i++)
        {
            uint ptr = pe.RawPtr[i], size = pe.Raw[i];
            if (size == 0 || ptr == 0 || ptr + size > b.Length) continue;
            var slice = new byte[size];
            Buffer.BlockCopy(b, (int)ptr, slice, 0, (int)size);
            parts.Add(pe.Names[i] + ":" + Md5Hex(slice)[..16]);
        }
        return parts.Count == 0 ? "" : string.Join("|", parts);
    }

    /// <summary>
    /// Rolling-hash fuzzy signature (7-byte weighted window, adaptive block size, ~64 pieces).
    /// Our own scheme — deliberately not presented as ssdeep-compatible.
    /// </summary>
    private static string Fuzzy(byte[] b, int start, int length)
    {
        if (length <= 0) return "";
        int block = ChooseBlock(length);
        int[] window = new int[7];
        uint rolling = 0;
        var piece = new List<byte>(96);
        var sb = new StringBuilder(1024);
        int pieces = 0;

        for (int i = start; i < start + length && i < b.Length; i++)
        {
            byte c = b[i];
            window[i % 7] = c;
            rolling = (uint)(window[0] * 3 + window[1] * 5 + window[2] * 7 + window[3] * 11 +
                             window[4] * 13 + window[5] * 17 + window[6] * 19);
            piece.Add(c);

            if (rolling % (uint)block == (uint)block - 1 && piece.Count > 0 && pieces < MaxPieces)
            {
                sb.Append(PieceHash(piece)).Append(':');
                piece.Clear();
                pieces++;
            }
        }

        if (piece.Count > 0 && pieces < MaxPieces)
        {
            sb.Append(PieceHash(piece));
            pieces++;
        }
        return sb.ToString();
    }

    private static string FuzzyStream(string path)
    {
        try
        {
            long len = new FileInfo(path).Length;
            int block = ChooseBlock(len);
            int[] window = new int[7];
            uint rolling = 0;
            var piece = new List<byte>(96);
            var sb = new StringBuilder(1024);
            int pieces = 0, index = 0;
            var buf = new byte[1024 * 1024];

            using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            int read;
            while ((read = fs.Read(buf, 0, buf.Length)) > 0 && pieces < MaxPieces)
            {
                for (int i = 0; i < read; i++)
                {
                    byte c = buf[i];
                    window[index % 7] = c;
                    rolling = (uint)(window[0] * 3 + window[1] * 5 + window[2] * 7 + window[3] * 11 +
                                     window[4] * 13 + window[5] * 17 + window[6] * 19);
                    piece.Add(c);
                    index++;

                    if (rolling % (uint)block == (uint)block - 1 && piece.Count > 0 && pieces < MaxPieces)
                    {
                        sb.Append(PieceHash(piece)).Append(':');
                        piece.Clear();
                        pieces++;
                    }
                }
            }

            if (piece.Count > 0 && pieces < MaxPieces)
            {
                sb.Append(PieceHash(piece));
                pieces++;
            }
            return sb.ToString();
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[FP] fuzzy stream failed for {path}: {ex.Message}");
            return "";
        }
    }

    private static int ChooseBlock(long length)
    {
        long target = Math.Max(1, length / 64);
        int shift = 6;
        while ((1L << shift) < target && shift < 22) shift++;
        return 1 << shift;
    }

    private static string PieceHash(List<byte> piece)
    {
        var hash = MD5.HashData(piece.ToArray());
        return Convert.ToHexString(hash, 0, 3).ToLowerInvariant();
    }

    private static string Md5Hex(byte[] data) => Convert.ToHexString(MD5.HashData(data)).ToLowerInvariant();
    private static string Md5Hex(string text) => Md5Hex(Encoding.UTF8.GetBytes(text));
    private static string ToHex(byte[] data) => Convert.ToHexString(data).ToLowerInvariant();

    private static string ReadAscii(byte[] b, int off, int max)
    {
        if (off < 0 || off >= b.Length) return "";
        int end = Math.Min(b.Length, off + max);
        int i = off;
        while (i < end && b[i] >= 0x20 && b[i] < 0x7F) i++;
        return Encoding.ASCII.GetString(b, off, i - off);
    }

    private static ushort ReadU16(byte[] b, int o) =>
        o + 2 <= b.Length ? (ushort)(b[o] | (b[o + 1] << 8)) : (ushort)0;

    private static uint ReadU32(byte[] b, int o) =>
        o + 4 <= b.Length ? (uint)(b[o] | (b[o + 1] << 8) | (b[o + 2] << 16) | (b[o + 3] << 24)) : 0u;

    private static ulong ReadU64(byte[] b, int o) =>
        o + 8 <= b.Length ? ReadU32(b, o) | ((ulong)ReadU32(b, o + 4) << 32) : 0UL;
}
