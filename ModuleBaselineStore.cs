using System.Security.Cryptography;
using System.Text;

namespace NexusAV.Engine;

/// <summary>
/// Persists known-good .text SHA-256 hashes and CPU-state anchors across boots.
/// HMAC-protected file under ProgramData — compared on the next engine start.
/// </summary>
public sealed class ModuleBaselineStore
{
    private const uint Magic = 0x4C42584Eu; // 'NXBL'
    private const int NameBytes = 32;
    private const int HashBytes = 32;
    private readonly string _path;
    private readonly byte[] _hmacKey;

    public ModuleBaselineStore()
    {
        string guid = "unknown";
        try
        {
            guid = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Cryptography")?.GetValue("MachineGuid") as string
                   ?? Environment.MachineName;
        }
        catch { guid = Environment.MachineName; }
        using var kdf = new HMACSHA256("NexusXDR-NXBL-v1"u8.ToArray());
        _hmacKey = kdf.ComputeHash(System.Text.Encoding.UTF8.GetBytes(guid));
        string dir = NexusDataDir.Ensure();
        _path = Path.Combine(dir, "module-baseline.bin");
    }

    public sealed class Snapshot
    {
        public required Dictionary<string, byte[]> Hashes { get; init; }
        public ulong IdtBase;
        public ulong GdtBase;
        public ulong Cr0;
        public ulong Cr3;
    }

    public Snapshot? Load()
    {
        try
        {
            if (!File.Exists(_path)) return null;
            byte[] raw = File.ReadAllBytes(_path);
            if (raw.Length < 8 + 32) return null;
            using var hmac = new HMACSHA256(_hmacKey);
            int macOff = raw.Length - 32;
            byte[] expected = hmac.ComputeHash(raw, 0, macOff);
            uint diff = 0;
            for (int i = 0; i < 32; i++) diff |= (uint)(expected[i] ^ raw[macOff + i]);
            if (diff != 0) return null;

            using var ms = new MemoryStream(raw, 0, macOff, writable: false);
            using var br = new BinaryReader(ms);
            if (br.ReadUInt32() != Magic) return null;
            uint count = br.ReadUInt32();
            var hashes = new Dictionary<string, byte[]>(StringComparer.OrdinalIgnoreCase);
            for (uint i = 0; i < count && i < 64; i++)
            {
                byte[] nameBytes = br.ReadBytes(NameBytes);
                byte[] hash = br.ReadBytes(HashBytes);
                int n = Array.IndexOf(nameBytes, (byte)0);
                string name = Encoding.ASCII.GetString(nameBytes, 0, n < 0 ? NameBytes : n);
                if (name.Length > 0) hashes[name] = hash;
            }
            return new Snapshot
            {
                Hashes = hashes,
                IdtBase = br.ReadUInt64(),
                GdtBase = br.ReadUInt64(),
                Cr0 = br.ReadUInt64(),
                Cr3 = br.ReadUInt64()
            };
        }
        catch { return null; }
    }

    public void Save(Snapshot snap)
    {
        using var ms = new MemoryStream();
        using (var bw = new BinaryWriter(ms, Encoding.ASCII, leaveOpen: true))
        {
            bw.Write(Magic);
            bw.Write((uint)snap.Hashes.Count);
            foreach (var kv in snap.Hashes)
            {
                byte[] name = new byte[NameBytes];
                byte[] src = Encoding.ASCII.GetBytes(kv.Key);
                Buffer.BlockCopy(src, 0, name, 0, Math.Min(src.Length, NameBytes));
                bw.Write(name);
                byte[] h = new byte[HashBytes];
                Buffer.BlockCopy(kv.Value, 0, h, 0, Math.Min(kv.Value.Length, HashBytes));
                bw.Write(h);
            }
            bw.Write(snap.IdtBase);
            bw.Write(snap.GdtBase);
            bw.Write(snap.Cr0);
            bw.Write(snap.Cr3);
        }
        byte[] body = ms.ToArray();
        using var hmac = new HMACSHA256(_hmacKey);
        byte[] mac = hmac.ComputeHash(body);
        File.WriteAllBytes(_path, body.Concat(mac).ToArray());
    }

    public int CompareAndUpdate(in KernelBridge.PrebootScanResult scan, out int mismatchCount)
    {
        mismatchCount = 0;
        var current = Extract(scan);
        Snapshot? prev = Load();
        if (prev != null)
        {
            foreach (var kv in current.Hashes)
            {
                if (prev.Hashes.TryGetValue(kv.Key, out byte[]? old) && old != null && old.Length == 32)
                {
                    bool same = true;
                    for (int i = 0; i < 32; i++)
                    {
                        if (old[i] != kv.Value[i]) { same = false; break; }
                    }
                    if (!same)
                    {
                        mismatchCount++;
                        Console.WriteLine($"[BASELINE] {kv.Key} .text hash changed since last boot");
                    }
                }
            }
            if (prev.IdtBase != 0 && prev.IdtBase != current.IdtBase)
            {
                mismatchCount++;
                Console.WriteLine($"[BASELINE] IDT changed 0x{prev.IdtBase:X16} -> 0x{current.IdtBase:X16}");
            }
            if (prev.GdtBase != 0 && prev.GdtBase != current.GdtBase)
            {
                mismatchCount++;
                Console.WriteLine($"[BASELINE] GDT changed 0x{prev.GdtBase:X16} -> 0x{current.GdtBase:X16}");
            }
        }
        else
        {
            Console.WriteLine("[BASELINE] No prior known-good store; pinning current .text hashes.");
        }

        // A mismatch means the current state is NOT known-good. Saving here would promote a
        // tampered image to the trusted baseline and silence every future boot comparison.
        if (mismatchCount > 0)
        {
            Console.WriteLine($"[BASELINE] {mismatchCount} mismatch(es) — known-good store NOT overwritten");
            return mismatchCount;
        }
        Save(current);
        return mismatchCount;
    }

    private static unsafe Snapshot Extract(in KernelBridge.PrebootScanResult scan)
    {
        var hashes = new Dictionary<string, byte[]>(StringComparer.OrdinalIgnoreCase);
        AddFile(hashes, in scan.File0);
        AddFile(hashes, in scan.File1);
        AddFile(hashes, in scan.File2);
        AddFile(hashes, in scan.File3);
        AddFile(hashes, in scan.File4);
        AddFile(hashes, in scan.File5);
        AddFile(hashes, in scan.File6);
        AddFile(hashes, in scan.File7);
        return new Snapshot
        {
            Hashes = hashes,
            IdtBase = scan.IdtBase,
            GdtBase = scan.GdtBase,
            Cr0 = scan.Cr0,
            Cr3 = scan.Cr3
        };
    }

    private static unsafe void AddFile(Dictionary<string, byte[]> hashes, in KernelBridge.PrebootFileResult file)
    {
        fixed (byte* p = file.FileName)
        {
            int n = 0;
            while (n < 32 && p[n] != 0) n++;
            if (n == 0) return;
            string name = Encoding.ASCII.GetString(p, n);
            byte[] h = new byte[32];
            fixed (byte* s = file.Sha256)
            {
                for (int i = 0; i < 32; i++) h[i] = s[i];
            }
            hashes[name] = h;
        }
    }
}
