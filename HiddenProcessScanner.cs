using System.Runtime.InteropServices;

namespace NexusAV.Engine;

/// <summary>
/// Cross-checks kernel-visible process IDs (NtQuerySystemInformation) against
/// CreateToolhelp32Snapshot. A PID present in one list and missing from the other
/// is the classic user-mode hide / DKOM discrepancy.
/// </summary>
public static unsafe partial class HiddenProcessScanner
{
    private const uint Th32csSnapProcess = 0x00000002;
    private const uint SystemProcessInformation = 5;
    private static readonly HashSet<uint> _reported = new();
    private static readonly object _lock = new();

    /// <summary>True if this PID was ever reported as a hidden-process discrepancy.</summary>
    public static bool IsReportedHidden(uint pid)
    {
        lock (_lock) return _reported.Contains(pid);
    }

    public static int Scan(Storyteller story)
    {
        Dictionary<uint, string> nt = QueryNtProcessIds();
        Dictionary<uint, string> snap = QueryToolhelpProcessIds();
        if (nt.Count == 0 || snap.Count == 0) return 0;

        int hits = 0;
        foreach (var kv in nt)
        {
            if (kv.Key <= 4) continue;
            if (snap.ContainsKey(kv.Key)) continue;
            hits += Report(story, kv.Key, kv.Value, "ntquery-not-in-toolhelp");
        }

        foreach (var kv in story.Processes)
        {
            if (kv.Key <= 4) continue;
            if (snap.ContainsKey(kv.Key) || nt.ContainsKey(kv.Key)) continue;
            hits += Report(story, kv.Key, kv.Value.ImageName, "kernel-notify-missing-from-usermode");
        }

        return hits;
    }

    private static int Report(Storyteller story, uint pid, string name, string source)
    {
        lock (_lock)
        {
            if (!_reported.Add(pid)) return 0;
        }
        var (score, allow, audit, act) = story.ReportHiddenProcess(pid, name, source);
        Console.WriteLine($"[HIDDEN-PROC] pid={pid} image={name} via={source} score={score}{(allow ? " [ALLOWLIST]" : "")}{(audit ? " [AUDIT]" : "")}{(act ? " [SHIELD]" : "")}");
        return 1;
    }

    private static Dictionary<uint, string> QueryToolhelpProcessIds()
    {
        var map = new Dictionary<uint, string>();
        IntPtr snap = CreateToolhelp32Snapshot(Th32csSnapProcess, 0);
        if (snap == IntPtr.Zero || snap == new IntPtr(-1)) return map;
        try
        {
            PROCESSENTRY32W pe = new() { dwSize = (uint)Marshal.SizeOf<PROCESSENTRY32W>() };
            if (!Process32FirstW(snap, ref pe)) return map;
            do
            {
                map[(uint)pe.th32ProcessID] = pe.szExeFile ?? "";
            } while (Process32NextW(snap, ref pe));
        }
        finally
        {
            CloseHandle(snap);
        }
        return map;
    }

    private static Dictionary<uint, string> QueryNtProcessIds()
    {
        var map = new Dictionary<uint, string>();
        int len = 1 << 20;
        IntPtr buf = Marshal.AllocHGlobal(len);
        try
        {
            int status;
            while (true)
            {
                status = NtQuerySystemInformation(SystemProcessInformation, buf, len, out int needed);
                if (status == unchecked((int)0xC0000004) || status == unchecked((int)0x80000005))
                {
                    Marshal.FreeHGlobal(buf);
                    len = Math.Max(needed + 4096, len * 2);
                    buf = Marshal.AllocHGlobal(len);
                    continue;
                }
                if (status < 0) return map;
                break;
            }

            byte* p = (byte*)buf;
            byte* end = p + len;
            int guard = 0;
            while (p + 80 <= end && guard++ < 16384)
            {
                uint next = *(uint*)p;
                IntPtr pidPtr = *(IntPtr*)(p + 0x50);
                uint pid = unchecked((uint)pidPtr.ToInt64());
                string name = ReadImageName(p);
                if (pid != 0 || name.Length > 0)
                    map[pid] = name;
                if (next == 0) break;
                p += next;
            }
        }
        catch { }
        finally
        {
            Marshal.FreeHGlobal(buf);
        }
        return map;
    }

    private static string ReadImageName(byte* entry)
    {
        try
        {
            ushort length = *(ushort*)(entry + 0x38);
            IntPtr buffer = *(IntPtr*)(entry + 0x40);
            if (buffer == IntPtr.Zero || length == 0) return "";
            return Marshal.PtrToStringUni(buffer, length / 2) ?? "";
        }
        catch { return ""; }
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct PROCESSENTRY32W
    {
        public uint dwSize;
        public uint cntUsage;
        public uint th32ProcessID;
        public nint th32DefaultHeapID;
        public uint th32ModuleID;
        public uint cntThreads;
        public uint th32ParentProcessID;
        public int pcPriClassBase;
        public uint dwFlags;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
        public string szExeFile;
    }

    [LibraryImport("kernel32.dll", SetLastError = true)]
    private static partial IntPtr CreateToolhelp32Snapshot(uint dwFlags, uint th32ProcessID);

    [LibraryImport("kernel32.dll", SetLastError = true, StringMarshalling = StringMarshalling.Utf16)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool Process32FirstW(IntPtr hSnapshot, ref PROCESSENTRY32W lppe);

    [LibraryImport("kernel32.dll", SetLastError = true, StringMarshalling = StringMarshalling.Utf16)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool Process32NextW(IntPtr hSnapshot, ref PROCESSENTRY32W lppe);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool CloseHandle(IntPtr hObject);

    [LibraryImport("ntdll.dll")]
    private static partial int NtQuerySystemInformation(uint SystemInformationClass, IntPtr SystemInformation, int SystemInformationLength, out int ReturnLength);
}
