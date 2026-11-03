using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.Win32;

namespace NexusAV.Engine;

public sealed class QuarantineEntry
{
    public string OriginalPath { get; set; } = string.Empty;
    public string QuarantinePath { get; set; } = string.Empty;
    public string SHA256 { get; set; } = string.Empty;
    public string ThreatName { get; set; } = string.Empty;
    public DateTime QuarantineDate { get; set; }
    public ulong FileSize { get; set; }
    public bool IsEncrypted { get; set; }
    /// <summary>0 = legacy per-session XOR (key not persisted, not recoverable), 1 = AES-256-GCM with the machine key.</summary>
    public int EncVersion { get; set; }
}

public sealed class QuarantineManager : IDisposable
{
    private const string QUARANTINE_DIR = "Quarantine";
    private const string QUARANTINE_DB = "quarantine_db.json";
    private readonly byte[] _quarantineKey;
    
    private readonly string _quarantinePath;
    private readonly string _dbPath;
    private readonly List<QuarantineEntry> _entries = new();
    private readonly object _lock = new();
    private int _disposed;

    public QuarantineManager()
    {
        _quarantinePath = NexusDataDir.Ensure(QUARANTINE_DIR);
        _dbPath = Path.Combine(_quarantinePath, QUARANTINE_DB);

        // Machine-bound key derived from the Windows MachineGuid. Unlike the old
        // per-session random XOR key (lost on restart => files unrecoverable), this key
        // is deterministic, so restore works after any restart. It is obfuscation from
        // casual disk browsing, not a secret from a local admin — quarantine's job is
        // "not executable, not runnable, restorable by the operator".
        _quarantineKey = DeriveMachineKey();

        LoadDatabase();
    }

    private static byte[] DeriveMachineKey()
    {
        string guid;
        try
        {
            using var k = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Cryptography");
            guid = k?.GetValue("MachineGuid")?.ToString() ?? Environment.MachineName;
        }
        catch
        {
            guid = Environment.MachineName;
        }
        byte[] material = Encoding.UTF8.GetBytes("NexusXDR.Quarantine.v1|" + guid + "|" + Environment.MachineName);
        return SHA256.HashData(material);
    }

    /// <summary>True when the path must never be quarantined (system/installed binaries — a false positive there is unrecoverable damage).</summary>
    private static bool IsProtectedPath(string fullPath)
    {
        string p = fullPath.TrimEnd('\\');
        string[] roots =
        {
            Environment.GetFolderPath(Environment.SpecialFolder.Windows),
            Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
            Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "NexusXDR")
        };
        foreach (string root in roots)
        {
            if (root.Length == 0) continue;
            if (p.StartsWith(root, StringComparison.OrdinalIgnoreCase) &&
                (p.Length == root.Length || p[root.Length] == '\\'))
                return true;
        }
        return false;
    }

    public bool QuarantineFile(string filePath, string threatName, out QuarantineEntry? entry)
    {
        ObjectDisposedException.ThrowIf(_disposed == 1, this);

        entry = null;

        if (!File.Exists(filePath))
            return false;

        lock (_lock)
        {
            try
            {
                if (IsProtectedPath(filePath))
                {
                    Console.WriteLine($"[QUARANTINE] REFUSED: {filePath} is under a protected system root — never quarantined");
                    return false;
                }

                // Calculate SHA256
                string sha256;
                using (var fs = File.OpenRead(filePath))
                using (var sha256Hash = SHA256.Create())
                {
                    byte[] hashBytes = sha256Hash.ComputeHash(fs);
                    sha256 = Convert.ToHexString(hashBytes).ToLowerInvariant();
                }

                // Generate quarantine filename
                string quarantineFileName = $"{Guid.NewGuid()}.quar";
                string quarantineFilePath = Path.Combine(_quarantinePath, quarantineFileName);

                // Read original file
                byte[] fileBytes = File.ReadAllBytes(filePath);

                // Encrypt file: AES-256-GCM, key derived from the machine GUID (restorable after restart)
                byte[] encryptedBytes = EncryptData(fileBytes, _quarantineKey);

                // Write to quarantine
                File.WriteAllBytes(quarantineFilePath, encryptedBytes);

                // Delete original file. If that fails (locked by a running process) the
                // quarantine blob is an orphan — remove it and fail honestly instead of
                // logging a quarantine that did not really happen.
                try
                {
                    File.Delete(filePath);
                }
                catch
                {
                    try { File.Delete(quarantineFilePath); } catch { }
                    throw;
                }

                // Create entry
                entry = new QuarantineEntry
                {
                    OriginalPath = filePath,
                    QuarantinePath = quarantineFilePath,
                    SHA256 = sha256,
                    ThreatName = threatName,
                    QuarantineDate = DateTime.Now,
                    FileSize = (ulong)fileBytes.Length,
                    IsEncrypted = true,
                    EncVersion = 1
                };

                _entries.Add(entry);
                SaveDatabase();

                return true;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[QUARANTINE] Failed to quarantine {filePath}: {ex.Message}");
                return false;
            }
        }
    }

    public bool RestoreFile(string quarantinePath, out string? restoredPath)
    {
        ObjectDisposedException.ThrowIf(_disposed == 1, this);

        restoredPath = null;

        lock (_lock)
        {
            try
            {
                var entry = _entries.FirstOrDefault(e => e.QuarantinePath == quarantinePath);
                if (entry == null)
                    return false;

                // Read encrypted file
                byte[] encryptedBytes = File.ReadAllBytes(quarantinePath);

                // Decrypt (versioned; legacy session-XOR entries carry no recoverable key)
                byte[] fileBytes;
                if (!entry.IsEncrypted || entry.EncVersion == 1)
                {
                    fileBytes = entry.IsEncrypted ? DecryptData(encryptedBytes, _quarantineKey) : encryptedBytes;
                }
                else
                {
                    Console.WriteLine($"[QUARANTINE] Cannot restore {quarantinePath}: legacy entry encrypted with a per-session key that was not persisted (pre-hardening build)");
                    return false;
                }

                // Integrity check: the blob must decrypt to exactly the hashed original.
                // A mismatch means corruption or tampering — refuse rather than write
                // a broken file over the user's disk.
                if (entry.SHA256.Length > 0)
                {
                    string got = Convert.ToHexString(SHA256.HashData(fileBytes)).ToLowerInvariant();
                    if (!string.Equals(got, entry.SHA256, StringComparison.OrdinalIgnoreCase))
                    {
                        Console.WriteLine($"[QUARANTINE] Refusing restore of {quarantinePath}: SHA256 mismatch (expected {entry.SHA256}, got {got})");
                        return false;
                    }
                }

                // Restore to original location. Recreate the directory if it is gone;
                // if something now occupies the original path, never overwrite it —
                // restore alongside as "name (restored).ext".
                string target = entry.OriginalPath;
                string? dir = Path.GetDirectoryName(target);
                if (!string.IsNullOrEmpty(dir) && !Directory.Exists(dir))
                    Directory.CreateDirectory(dir);
                if (File.Exists(target))
                {
                    string stem = Path.GetFileNameWithoutExtension(target);
                    string ext = Path.GetExtension(target);
                    target = Path.Combine(dir ?? "", stem + " (restored)" + ext);
                }
                File.WriteAllBytes(target, fileBytes);

                // Delete quarantine file
                File.Delete(quarantinePath);

                // Remove from database
                _entries.Remove(entry);
                SaveDatabase();

                restoredPath = target;
                return true;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[QUARANTINE] Failed to restore {quarantinePath}: {ex.Message}");
                return false;
            }
        }
    }

    public bool DeleteQuarantinedFile(string quarantinePath)
    {
        ObjectDisposedException.ThrowIf(_disposed == 1, this);

        lock (_lock)
        {
            try
            {
                var entry = _entries.FirstOrDefault(e => e.QuarantinePath == quarantinePath);
                if (entry == null)
                    return false;

                // Delete quarantine file
                File.Delete(quarantinePath);

                // Remove from database
                _entries.Remove(entry);
                SaveDatabase();

                return true;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[QUARANTINE] Failed to delete {quarantinePath}: {ex.Message}");
                return false;
            }
        }
    }

    public List<QuarantineEntry> GetQuarantineEntries()
    {
        lock (_lock)
        {
            return new List<QuarantineEntry>(_entries);
        }
    }

    // AES-256-GCM. Layout: [ver=1][nonce:12][tag:16][ciphertext]. The tag makes tampering
    // with a quarantined file a hard, detectable failure instead of silent corruption.
    private static byte[] EncryptData(byte[] data, byte[] key)
    {
        byte[] nonce = RandomNumberGenerator.GetBytes(12);
        byte[] tag = new byte[16];
        byte[] cipher = new byte[data.Length];
        using (var aes = new AesGcm(key, 16))
        {
            aes.Encrypt(nonce, data, cipher, tag);
        }
        byte[] outBuf = new byte[1 + 12 + 16 + cipher.Length];
        outBuf[0] = 1;
        Buffer.BlockCopy(nonce, 0, outBuf, 1, 12);
        Buffer.BlockCopy(tag, 0, outBuf, 13, 16);
        Buffer.BlockCopy(cipher, 0, outBuf, 29, cipher.Length);
        return outBuf;
    }

    private static byte[] DecryptData(byte[] encrypted, byte[] key)
    {
        if (encrypted.Length < 29 || encrypted[0] != 1)
            throw new InvalidDataException("unrecognized quarantine file format");
        byte[] nonce = new byte[12];
        byte[] tag = new byte[16];
        byte[] cipher = new byte[encrypted.Length - 29];
        Buffer.BlockCopy(encrypted, 1, nonce, 0, 12);
        Buffer.BlockCopy(encrypted, 13, tag, 0, 16);
        Buffer.BlockCopy(encrypted, 29, cipher, 0, cipher.Length);
        byte[] plain = new byte[cipher.Length];
        using (var aes = new AesGcm(key, 16))
        {
            aes.Decrypt(nonce, cipher, tag, plain);
        }
        return plain;
    }

    private void LoadDatabase()
    {
        lock (_lock)
        {
            if (!File.Exists(_dbPath))
                return;

            try
            {
                string json = File.ReadAllText(_dbPath);
                _entries.Clear();
                var entries = JsonSerializer.Deserialize(json, QuarantineJsonContext.Default.ListQuarantineEntry);
                if (entries != null)
                {
                    _entries.AddRange(entries);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[QUARANTINE] Failed to load database: {ex.Message}");
            }
        }
    }

    private void SaveDatabase()
    {
        lock (_lock)
        {
            string tmp = _dbPath + ".tmp";
            try
            {
                string json = JsonSerializer.Serialize(_entries, QuarantineJsonContext.Default.ListQuarantineEntry);
                // Write-then-rename: a crash mid-save leaves the previous DB intact instead of
                // a truncated JSON that fails to deserialize on the next start.
                File.WriteAllText(tmp, json);
                File.Move(tmp, _dbPath, overwrite: true);
            }
            catch (Exception ex)
            {
                try { if (File.Exists(tmp)) File.Delete(tmp); } catch { }
                Console.WriteLine($"[QUARANTINE] Failed to save database: {ex.Message}");
            }
        }
    }

    public void Dispose()
    {
        if (Interlocked.Exchange(ref _disposed, 1) == 0)
        {
            SaveDatabase();
        }
    }
}

// Source-generated serialization: reflection-based JsonSerializer is disabled under
// PublishAot=true, which silently broke quarantine DB persistence at runtime.
[JsonSourceGenerationOptions(WriteIndented = true)]
[JsonSerializable(typeof(List<QuarantineEntry>))]
internal sealed partial class QuarantineJsonContext : JsonSerializerContext
{
}
