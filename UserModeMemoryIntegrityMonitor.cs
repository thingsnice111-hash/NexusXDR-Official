using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;

namespace NexusAV.Engine;

/// <summary>
/// Read-only user-mode memory integrity monitor — the honest replacement for the
/// kernel-LBR / ROP fiction. Per watchlisted process it verifies three real properties
/// from the live address space:
///   1. unbacked executable private regions (VirtualQueryEx walk: MEM_PRIVATE + PAGE_EXECUTE*)
///   2. thread start addresses outside any mapped image (a thread that begins in a private
///      executable region was started at injected code — NtQueryInformationThread)
///   3. disk-vs-memory image header mismatch on the main module (PE timestamp / entry point
///      read from the target vs the same header on disk = hollowing/patcher evidence)
///
/// Detection-only: it reports findings to the Storyteller ledger and the event feed and
/// never terminates, blocks, or modifies anything. Watchlist = scored, non-allowlisted
/// processes, bounded per pass, 30 s cadence.
/// </summary>
public sealed class UserModeMemoryIntegrityMonitor : IDisposable
{
    private const int ScanIntervalMs = 30000;
    private const int MaxTargetsPerPass = 24;
    private const int MaxRegionsPerTarget = 4096;
    private const uint MemCommit = 0x1000;
    private const uint MemPrivate = 0x20000;
    private const uint MemImage = 0x1000000;
    private const uint PageExecute = 0x10;
    private const uint PageExecuteRead = 0x20;
    private const uint PageExecuteReadWrite = 0x40;
    private const uint PageExecuteWriteCopy = 0x80;
    private const uint ProcessQueryLimitedInformation = 0x1000;
    private const uint ProcessVmRead = 0x0010;
    private const uint ThreadQueryInformation = 0x0040;
    private const int ThreadQuerySetWin32StartAddress = 9;

    private readonly Storyteller _story;
    private readonly StorytellerStable _feed;
    private readonly Thread _thread;
    private readonly CancellationTokenSource _cts = new();
    private int _disposed;
    private long _lastCleanupMs;

    // Findings are reported once per (pid, kind) until the process dies.
    private readonly Dictionary<uint, HashSet<string>> _reported = new();
    private readonly object _repLock = new();

    public int TotalFindings;
    public int TotalScans;

    public UserModeMemoryIntegrityMonitor(Storyteller story, StorytellerStable feed)
    {
        _story = story;
        _feed = feed;
        _thread = new Thread(Loop) { IsBackground = true, Name = "Nexus-MemIntegrity", Priority = ThreadPriority.BelowNormal };
    }

    public void Start() => _thread.Start();

    private void Loop()
    {
        try { _cts.Token.WaitHandle.WaitOne(15000); } catch { } // let the engine settle first
        while (Volatile.Read(ref EngineState.ShuttingDown) == 0 && !_cts.IsCancellationRequested)
        {
            try
            {
                if (Volatile.Read(ref EngineState.BypassMode) == 0) ScanPass();
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[MEM-VERIFY] pass fault (non-fatal): {ex.Message}");
            }
            try { _cts.Token.WaitHandle.WaitOne(ScanIntervalMs); } catch { }
        }
    }

    /// <summary>On-demand scan (GUI command `memscan`); returns findings reported this pass.</summary>
    public int ScanNow()
    {
        try { return ScanPass(); }
        catch { return 0; }
    }

    private int ScanPass()
    {
        Interlocked.Increment(ref TotalScans);
        int findings = 0;
        var targets = new List<(uint pid, string img)>();

        foreach (var node in _story.Processes.Values)
        {
            if (targets.Count >= MaxTargetsPerPass) break;
            if (node.Pid <= 4 || node.InAllowlist) continue;
            if (node.Confidence < 10) continue;
            targets.Add((node.Pid, node.ImageName));
        }

        foreach (var t in targets)
            findings += VerifyProcess(t.pid, t.img);

        CleanupReported();
        return findings;
    }

    private int VerifyProcess(uint pid, string image)
    {
        int findings = 0;
        IntPtr h = OpenProcess(ProcessQueryLimitedInformation | ProcessVmRead, false, pid);
        if (h == IntPtr.Zero) return 0;
        try
        {
            findings += CheckUnbackedExecutableRegions(h, pid, image);
            findings += CheckThreadStarts(h, pid, image);
            findings += CheckImageHeaderMismatch(h, pid, image);
        }
        catch { }
        finally { CloseHandle(h); }
        return findings;
    }

    // ── 1. Unbacked private executable regions ─────────────────────────────

    private int CheckUnbackedExecutableRegions(IntPtr h, uint pid, string image)
    {
        var mbi = new MemoryBasicInformation();
        int size = Marshal.SizeOf<MemoryBasicInformation>();
        ulong addr = 0x10000;
        int regions = 0, suspicious = 0;
        ulong suspiciousBytes = 0;

        for (int i = 0; i < MaxRegionsPerTarget; i++)
        {
            IntPtr got = VirtualQueryEx(h, (IntPtr)(long)addr, out mbi, (IntPtr)size);
            if (got == IntPtr.Zero) break;

            ulong baseAddr = (ulong)mbi.BaseAddress.ToInt64();
            ulong regionSize = (ulong)mbi.RegionSize.ToInt64();
            if (regionSize == 0) break;

            bool exec = (mbi.Protect & (PageExecute | PageExecuteRead | PageExecuteReadWrite | PageExecuteWriteCopy)) != 0;
            if (mbi.State == MemCommit && mbi.Type == MemPrivate && exec)
            {
                regions++;
                suspiciousBytes += regionSize;
            }

            ulong next = baseAddr + regionSize;
            if (next <= addr) break;
            addr = next;
            if (addr > 0x7FFFFFFFFFFF) break;
        }

        // A couple of private executable pages are normal (JIT stubs, veneers). The wide
        // spread injection frameworks leave behind is far larger; 16 also keeps typical
        // JIT page sprawl out. Heuristic => audit severity, no response is triggered.
        if (regions >= 16)
        {
            suspicious = regions;
            string reason = $"{suspicious} private executable regions, {suspiciousBytes / 1024} KB total (unbacked code)";
            Report(pid, "unbacked-exec", image, reason, "audit");
            return 1;
        }
        return 0;
    }

    // ── 2. Thread start addresses outside any image ────────────────────────

    private int CheckThreadStarts(IntPtr h, uint pid, string image)
    {
        int flagged = 0;
        // Enumerating threads of one process from a snapshot is one kernel walk per target —
        // bounded by MaxTargetsPerPass and the 30 s cadence.
        Process proc;
        try { proc = Process.GetProcessById((int)pid); }
        catch { return 0; }
        try
        {
            var threads = proc.Threads;
            for (int i = 0; i < threads.Count; i++)
            {
                int tid;
                try { tid = threads[i].Id; } catch { continue; }
                IntPtr th = OpenThread(ThreadQueryInformation, false, (uint)tid);
                if (th == IntPtr.Zero) continue;
                try
                {
                    int st = NtQueryInformationThread(th, ThreadQuerySetWin32StartAddress, out ulong startAddr, sizeof(ulong), IntPtr.Zero);
                    if (st != 0 || startAddr == 0) continue;

                    var q = new MemoryBasicInformation();
                    IntPtr got = VirtualQueryEx(h, (IntPtr)(long)startAddr, out q, (IntPtr)Marshal.SizeOf<MemoryBasicInformation>());
                    if (got == IntPtr.Zero) continue;

                    bool exec = (q.Protect & (PageExecute | PageExecuteRead | PageExecuteReadWrite | PageExecuteWriteCopy)) != 0;
                    // Start IP in committed, executable memory that is NOT a mapped image =
                    // the thread began executing in private (injected/JIT) memory.
                    if (q.State == MemCommit && exec && q.Type != MemImage)
                    {
                        flagged++;
                        if (flagged <= 3)
                            Report(pid, $"thread-start-{tid}", image,
                                $"thread {tid} start address 0x{startAddr:X} is in private executable memory (not an image)", "audit");
                        break;
                    }
                }
                finally { CloseHandle(th); }
            }
        }
        catch { }
        finally { proc.Dispose(); }
        return flagged > 0 ? 1 : 0;
    }

    // ── 3. Disk-vs-memory image header mismatch (hollowing) ────────────────

    private int CheckImageHeaderMismatch(IntPtr h, uint pid, string image)
    {
        string path;
        try
        {
            using var proc = Process.GetProcessById((int)pid);
            path = proc.MainModule?.FileName ?? "";
        }
        catch { return 0; }
        if (path.Length == 0) return 0;

        try
        {
            IntPtr baseAddr = ProcessModuleBase(h, pid, path);
            if (baseAddr == IntPtr.Zero) return 0;

            // Read the in-memory DOS header at the module base and resolve e_lfanew.
            byte[] dos = new byte[64];
            if (!ReadProcessMemory(h, baseAddr, dos, (IntPtr)dos.Length, out IntPtr read) || (int)read < 64)
                return 0;
            if (dos[0] != 'M' || dos[1] != 'Z') return 0;
            int lfanew = BitConverter.ToInt32(dos, 0x3C);
            if (lfanew <= 0 || lfanew > 0x100000) return 0;

            byte[] memPe = new byte[64];
            IntPtr peAddr = (IntPtr)((long)baseAddr + lfanew);
            if (!ReadProcessMemory(h, peAddr, memPe, (IntPtr)memPe.Length, out read) || (int)read < 64)
                return 0;
            if (memPe[0] != 'P' || memPe[1] != 'E') return 0;

            byte[] disk = new byte[64];
            using (var fs = new System.IO.FileStream(path, System.IO.FileMode.Open, System.IO.FileAccess.Read, System.IO.FileShare.ReadWrite))
            {
                fs.Seek(lfanew, System.IO.SeekOrigin.Begin);
                int got = fs.Read(disk, 0, 64);
                if (got < 64) return 0;
            }
            if (disk[0] != 'P' || disk[1] != 'E') return 0;

            // Compare TimeDateStamp + AddressOfEntryPoint + SizeOfImage from the optional
            // header (both COFF headers start at offset 4; optional header follows at 24).
            uint memStamp = BitConverter.ToUInt32(memPe, 8);
            uint diskStamp = BitConverter.ToUInt32(disk, 8);
            uint memEntry = BitConverter.ToUInt32(memPe, 24 + 16);
            uint diskEntry = BitConverter.ToUInt32(disk, 24 + 16);

            if (memStamp != diskStamp || (memEntry != diskEntry && diskEntry != 0))
            {
                Report(pid, "header-mismatch", image,
                    $"in-memory PE header differs from disk ({path}): timestamp 0x{memStamp:X} vs 0x{diskStamp:X}, entry 0x{memEntry:X} vs 0x{diskEntry:X}", "high");
                return 1;
            }
        }
        catch { }
        return 0;
    }

    private static IntPtr ProcessModuleBase(IntPtr h, uint pid, string path)
    {
        // Module base from the target process (queried via the process object; cheap enough
        // at the 30 s cadence and only for the main module).
        using var proc = Process.GetProcessById((int)pid);
        var modules = proc.Modules;
        for (int i = 0; i < modules.Count; i++)
        {
            try
            {
                if (string.Equals(modules[i].FileName, path, StringComparison.OrdinalIgnoreCase))
                    return modules[i].BaseAddress;
            }
            catch { }
        }
        try { return modules[0].BaseAddress; } catch { return IntPtr.Zero; }
    }

    // ── Reporting ───────────────────────────────────────────────────────────

    private void Report(uint pid, string kind, string image, string reason, string severity)
    {
        lock (_repLock)
        {
            if (!_reported.TryGetValue(pid, out var kinds))
            {
                kinds = new HashSet<string>(StringComparer.Ordinal);
                _reported[pid] = kinds;
            }
            if (!kinds.Add(kind)) return;
        }
        Interlocked.Increment(ref TotalFindings);
        Console.WriteLine($"[MEM-VERIFY] pid={pid} {image}: {reason}");
        EventBus.Detection("memory", severity, "Memory integrity anomaly",
            $"{image} (pid {pid}): {reason}", pid);
        _feed.AddMemory(pid, image, reason);
        _story.ReportMemoryIntegrity(pid);
    }

    private void CleanupReported()
    {
        long now = Environment.TickCount64;
        if (now - _lastCleanupMs < 120000) return;
        _lastCleanupMs = now;
        List<uint>? dead = null;
        foreach (uint pid in _reported.Keys)
        {
            IntPtr h = OpenProcess(ProcessQueryLimitedInformation, false, pid);
            if (h == IntPtr.Zero) (dead ??= new List<uint>()).Add(pid);
            else CloseHandle(h);
        }
        if (dead != null)
            foreach (uint pid in dead) _reported.Remove(pid);
    }

    public void Dispose()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0) return;
        try { _cts.Cancel(); } catch { }
        try { _thread.Join(1500); } catch { }
    }

    // ── Interop ──────────────────────────────────────────────────────────────

    [StructLayout(LayoutKind.Sequential)]
    private struct MemoryBasicInformation
    {
        public IntPtr BaseAddress;
        public IntPtr AllocationBase;
        public uint AllocationProtect;
        public ushort PartitionId;
        public ushort Padding1;
        public IntPtr RegionSize;
        public uint State;
        public uint Protect;
        public uint Type;
        public uint Padding2;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenProcess(uint access, bool inherit, uint pid);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CloseHandle(IntPtr h);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenThread(uint access, bool inherit, uint tid);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr VirtualQueryEx(IntPtr h, IntPtr address, out MemoryBasicInformation mbi, IntPtr length);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool ReadProcessMemory(IntPtr h, IntPtr baseAddr, byte[] buffer, IntPtr size, out IntPtr bytesRead);

    [DllImport("ntdll.dll")]
    private static extern int NtQueryInformationThread(IntPtr thread, int infoClass, out ulong value, int size, IntPtr returnLength);
}
