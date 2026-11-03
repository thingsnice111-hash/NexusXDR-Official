using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;

namespace NexusAV.Engine;

/// <summary>
/// Windows exploit-mitigation policies, read and written through the public
/// <c>Get/SetProcessMitigationPolicy</c> APIs only — no code is injected into any process.
///
/// Two jobs:
///  * <see cref="ApplySelfHardening"/> arms the engine's own process (ACG, CFG, DEP, ASLR,
///    strict handle checks, extension-point and image-load restrictions).
///  * <see cref="QueryProcess"/> reads the live policy set of any other process with a
///    PROCESS_QUERY_LIMITED_INFORMATION handle, so the console can show what is really
///    enforced instead of guessing from the image name.
///
/// Mitigation policies are one-way: once ACG is set it cannot be cleared in a live process.
/// Recovery therefore means "do not apply it next start", which is what <see cref="HardeningGuard"/>
/// implements: a pending marker written before ACG is armed and cleared only when the engine
/// reaches its healthy-startup checkpoint.
/// </summary>
public static class ProcessMitigations
{
    // ── Win32 ──────────────────────────────────────────────────────────────

    private const uint ProcessQueryLimitedInformation = 0x1000;

    private enum MitigationPolicy
    {
        Dep = 0,
        Aslr = 1,
        DynamicCode = 2,
        StrictHandle = 3,
        SystemCallDisable = 4,
        ExtensionPointDisable = 6,
        ControlFlowGuard = 7,
        Signature = 8,
        FontDisable = 9,
        ImageLoad = 10,
        UserShadowStack = 15,
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenProcess(uint access, bool inheritHandle, uint processId);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr handle);

    [DllImport("kernel32.dll")]
    private static extern IntPtr GetCurrentProcess();

    // Every published mitigation struct is a DWORD bitfield union, so one uint covers all of
    // them and stays trivially AOT-safe (no bitfield marshalling, no reflection).
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool GetProcessMitigationPolicy(
        IntPtr process, int policy, ref uint buffer, IntPtr size);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool SetProcessMitigationPolicy(
        int policy, ref uint buffer, IntPtr size);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool QueryFullProcessImageNameW(
        IntPtr process, int flags, StringBuilder image, ref int size);

    private static IntPtr SizeOfUint => new IntPtr(4);

    // ── decoding tables ────────────────────────────────────────────────────

    public sealed record PolicyInfo(int Id, string Label, string[] BitNames);

    private static readonly PolicyInfo[] Policies =
    {
        new(0,  "DEP",              new[] { "DepEnabled", "DisallowAtlThunkExecute" }),
        new(1,  "ASLR",             new[] { "BottomUpRandomization", "ForceRandomizer", "TopDownRandomization" }),
        new(2,  "DynamicCode",      new[] { "ProhibitDynamicCode", "AllowThreadOptOut", "AllowRemoteDowngrades" }),
        new(3,  "StrictHandle",     new[] { "InvalidHandleCloseThrows", "InvalidHandleUseThrows" }),
        new(4,  "Win32kSyscall",    new[] { "DisableWin32SystemCalls" }),
        new(6,  "ExtensionPoint",   new[] { "DisableExtensionPoints" }),
        new(7,  "ControlFlowGuard", new[] { "Enable", "ExportSuppression", "StrictMode", "", "Hotpatch", "CertRollback" }),
        new(8,  "Signature",        new[] { "MicrosoftSignedOnly", "StoreSignedOnly", "SignedMitigation", "DynamicCode" }),
        new(9,  "Font",             new[] { "DisableNonSystemFonts", "AuditNonSystemFontLoading" }),
        new(10, "ImageLoad",        new[] { "NoRemoteImages", "NoLowMandatoryLabelImages", "PreferSystem32Images" }),
        new(15, "UserShadowStack",  new[] { "EnableUserShadowStack", "AuditUserShadowStack", "SetContextIpValidation", "AuditSetContextIpValidation" }),
    };

    private static string Decode(PolicyInfo p, uint flags)
    {
        if (flags == 0) return "off";
        var sb = new StringBuilder();
        uint remaining = flags;
        for (int i = 0; i < p.BitNames.Length; i++)
        {
            uint bit = 1u << i;
            if ((flags & bit) == 0) continue;
            remaining &= ~bit;
            if (p.BitNames[i].Length == 0) continue;
            if (sb.Length > 0) sb.Append('+');
            sb.Append(p.BitNames[i]);
        }
        if (remaining != 0)
        {
            if (sb.Length > 0) sb.Append('+');
            sb.Append("0x").Append(remaining.ToString("X", CultureInfo.InvariantCulture));
        }
        return sb.Length == 0 ? "0x" + flags.ToString("X", CultureInfo.InvariantCulture) : sb.ToString();
    }

    // ── self hardening ─────────────────────────────────────────────────────

    /// <summary>
    /// Outcome of arming the engine's own process: what was requested, what the OS reports as
    /// enforced after read-back, and what the rollback guard decided about ACG.
    /// </summary>
    public sealed record SelfHardeningResult(
        bool Applied,
        bool AcgRequested,
        bool AcgActive,
        string AcgSource,
        IReadOnlyList<string> Enabled,
        IReadOnlyList<string> Failed,
        string Detail,
        string Guard);

    public static bool LastAcgRequested { get; private set; }
    public static bool LastAcgActive { get; private set; }
    public static string LastAcgSource { get; private set; } = "not_run";
    public static string LastDetail { get; private set; } = "hardening has not run this process";

    /// <summary>Current process's live policy set, straight from the OS.</summary>
    public static ProcessMitigationInfo QuerySelf() =>
        QueryHandle(GetCurrentProcess(), (uint)Environment.ProcessId, "self");

    /// <summary>
    /// Startup entry point. Decides whether ACG may be armed from the rollback guard state,
    /// writes the pending marker before it is armed, then applies and reads everything back.
    /// </summary>
    public static SelfHardeningResult RunStartupHardening(bool noHarden, bool noAcg, bool forceAcg)
    {
        if (noHarden)
        {
            var off = new SelfHardeningResult(false, false, false, "disabled_flag",
                Array.Empty<string>(), Array.Empty<string>(), "hardening skipped by --no-harden",
                "guard untouched");
            Remember(off);
            return off;
        }

        HardeningGuard.State guard = HardeningGuard.Load();
        bool wantAcg;
        string guardNote;
        string acgReason;

        if (guard.Pending)
        {
            // The marker was armed last run and the healthy checkpoint never ran: that run died
            // after ACG was set. ACG cannot be lifted from a live process, so the only recovery
            // is to stop arming it. Latched until the guard file is deleted.
            guard.Pending = false;
            guard.AcgDisabled = true;
            guard.Failures++;
            wantAcg = false;
            acgReason = "auto_rollback";
            guardNote = "AUTO_ROLLBACK: predchozi beh umrl po nasazeni ACG pred init checkpointem; " +
                        "ACG je trvale vypnute (vymaz " + HardeningGuard.FilePath + " pro obnoveni)";
        }
        else if (guard.AcgDisabled)
        {
            wantAcg = false;
            acgReason = "rolled_back";
            guardNote = "ACG trvale vypnuto rollback hlidkou (vymaz " + HardeningGuard.FilePath + " pro obnoveni)";
        }
        else if (noAcg)
        {
            wantAcg = false;
            acgReason = "flag_no_acg";
            guardNote = "ACG vypnuto przekazem --no-acg";
        }
        else if (RunsOnJitRuntime && !forceAcg)
        {
            // Measured 2026-10-18: with ProhibitDynamicCode armed, the CoreCLR/JIT engine died in
            // ~0.1 s with 0xE0434352 — it cannot compile the methods it still needs. ACG only makes
            // sense on a genuinely native-AOT binary, so it is refused up front instead of being
            // armed, crashing and rolling back on every fresh guard file.
            wantAcg = false;
            acgReason = "jit_incompatible";
            guardNote = "ACG nasazene nebylo: engine behi na CoreCLR JIT (nactena coreclr.dll), " +
                        "ktery za chodu generuje spustitelne stranky — ACG by ho zabil. " +
                        "Test: --force-acg, nasadi se po realnem AOT publish.";
        }
        else
        {
            wantAcg = true;
            acgReason = forceAcg ? "forced" : "user";
            guard.Pending = true;
            guardNote = "ACG nasazeno, pending checkpoint marker zapsan (prikaz: " +
                        (forceAcg ? "--force-acg" : "default") + ")";
        }

        guard.LastDetail = DateTime.UtcNow.ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture);
        HardeningGuard.Save(guard);

        var result = ApplySelfHardening(wantAcg, acgReason) with { Guard = guardNote };
        Remember(result);
        return result;
    }

    private static int? _jitRuntime;

    /// <summary>
    /// True when this process is running on the CoreCLR JIT. The compiler-folded
    /// <c>RuntimeFeature.IsDynamicCodeSupported</c> is useless here — it is baked from the
    /// PublishAot project property, so a plain framework-dependent build built with PublishAot=true
    /// reports "no JIT" while coreclr.dll is loaded and compiling. Only the loaded module list is
    /// a real answer, so probe that once, over our own process.
    /// </summary>
    public static bool RunsOnJitRuntime
    {
        get
        {
            int? cached = _jitRuntime;
            if (cached != null) return cached == 1;
            int found = 0;
            try
            {
                using var self = System.Diagnostics.Process.GetCurrentProcess();
                foreach (System.Diagnostics.ProcessModule m in self.Modules)
                {
                    string name;
                    try { name = m.ModuleName; } catch { continue; }
                    if (string.Equals(name, "coreclr.dll", StringComparison.OrdinalIgnoreCase)) { found = 1; break; }
                }
            }
            catch { }
            _jitRuntime = found;
            return found == 1;
        }
    }

    private static void Remember(SelfHardeningResult r)
    {
        LastAcgRequested = r.AcgRequested;
        LastAcgActive = r.AcgActive;
        LastAcgSource = r.AcgSource;
        var sb = new StringBuilder();
        sb.Append(r.Detail);
        foreach (string f in r.Failed) sb.Append(" | refused: ").Append(f);
        if (r.Guard.Length > 0) sb.Append(" | ").Append(r.Guard);
        string text = sb.ToString();
        LastDetail = text.Length > 400 ? text.Substring(0, 400) + "..." : text;
    }

    /// <summary>
    /// Called once the engine finished initializing: proves the hardened process is viable and
    /// releases the ACG pending marker. If this never runs, the next start rolls ACG back.
    /// </summary>
    public static void CheckpointHealthy()
    {
        HardeningGuard.State guard = HardeningGuard.Load();
        if (!guard.Pending && guard.Failures == 0 && !guard.AcgDisabled) return;
        guard.Pending = false;
        guard.Failures = 0;
        HardeningGuard.Save(guard);
    }

    /// <summary>
    /// Arms the engine's own mitigations. Everything except ACG is applied unconditionally;
    /// ACG is gated by <paramref name="wantAcg"/> and re-checked by reading the policy back.
    /// Never throws — the engine must boot even if hardening is refused.
    /// </summary>
    public static SelfHardeningResult ApplySelfHardening(bool wantAcg, string acgReason)
    {
        var enabled = new List<string>();
        var failed = new List<string>();
        IntPtr self = GetCurrentProcess();
        uint selfPid = (uint)Environment.ProcessId;

        // DEP: non-executable heap + block the old ATL thunk trick.
        // ASLR: force randomization for images lacking the DYNAMIC_BASE flag too.
        // StrictHandle: close/use of an invalid handle raises instead of corrupting state.
        // ExtensionPoint: no shim / AppInit-style third-party injection points.
        // ImageLoad: refuse images from remote shares, prefer %WINDIR%\System32 on redirection.
        // CFG: validate guarded indirect calls and suppress non-exported CP enumeration.
        var requests = new (MitigationPolicy Policy, uint Flags, string Label)[]
        {
            (MitigationPolicy.Dep, 0x3, "DEP(AtlThunk)"),
            (MitigationPolicy.Aslr, 0x7, "ASLR(force)"),
            (MitigationPolicy.StrictHandle, 0x3, "StrictHandle"),
            (MitigationPolicy.ExtensionPointDisable, 0x1, "ExtensionPointDisable"),
            (MitigationPolicy.ImageLoad, 0x5, "ImageLoad(no-remote,system32)"),
            (MitigationPolicy.ControlFlowGuard, 0x3, "CFG(suppression)"),
        };
        if (wantAcg)
            requests = new[] { (MitigationPolicy.DynamicCode, 1u, "ACG") }.Concat(requests).ToArray();

        // Deliberately NOT applied, and why the console says so:
        //  * Signature(MicrosoftSignedOnly) would refuse the engine's own unsigned dependencies.
        //  * ChildProcess(DisableChildProcesses) would stop the engine launching its helpers.
        //  * Win32k / Font restrictions buy nothing for a headless native process.

        foreach (var (policy, flags, label) in requests)
        {
            uint buf = flags;
            bool ok;
            try { ok = SetProcessMitigationPolicy((int)policy, ref buf, SizeOfUint); }
            catch (EntryPointNotFoundException) { ok = false; }
            if (!ok) failed.Add(label + " :: " + SetFailureHint(Marshal.GetLastWin32Error()));
        }

        // Read every policy back from the live process — the report reflects what the OS
        // actually enforced, not what we asked for.
        var info = QueryHandle(self, selfPid, "self");
        foreach (var p in info.Policies)
        {
            if (p.Value != 0) enabled.Add(p.Name + "=" + Decode(p.Info, p.Value));
        }

        bool acgActive = (info.FlagsOf("DynamicCode") & 1u) != 0;
        string detail = $"{enabled.Count} policies enforced, {failed.Count} refused";
        return new SelfHardeningResult(true, wantAcg, acgActive,
            AcgSourceLabel(wantAcg, acgActive, acgReason), enabled, failed, detail, "");
    }

    /// <summary>
    /// Why ACG is or isn't armed. "active" is only ever reported when the read-back says the OS
    /// really enforces ProhibitDynamicCode — asking for it is not the same as having it.
    /// </summary>
    private static string AcgSourceLabel(bool wantAcg, bool acgActive, string acgReason)
    {
        if (acgActive) return "active";
        if (wantAcg) return "set_failed";
        return string.IsNullOrEmpty(acgReason) ? "not_requested" : acgReason;
    }

    /// <summary>
    /// SetProcessMitigationPolicy only accepts a policy that is not already frozen. On a running
    /// process DEP is fixed at creation (50) and a CFG bit that the loader already turned on
    /// cannot be widened (5) — so say that instead of reporting a bare error code.
    /// </summary>
    private static string SetFailureHint(int err) => err switch
    {
        50 => "err50 already fixed by the loader at process creation",
        5 => "err5 policy already armed by the loader, extra bits cannot be added",
        87 => "err87 policy not supported by this OS build",
        _ => "err" + err
    };

    // ── cross-process query ────────────────────────────────────────────────

    public sealed record PolicyValue(PolicyInfo Info, string Name, uint Value);

    public sealed record ProcessMitigationInfo(
        uint Pid,
        string Image,
        IReadOnlyList<PolicyValue> Policies,
        string Error)
    {
        /// <summary>Raw enforcement bits for one policy label; 0 when the OS refused the query.</summary>
        public uint FlagsOf(string policyName)
        {
            foreach (var p in Policies)
                if (string.Equals(p.Name, policyName, StringComparison.Ordinal)) return p.Value;
            return 0;
        }

        public string DecodedSummary()
        {
            var sb = new StringBuilder();
            foreach (var p in Policies)
            {
                if (p.Value == 0) continue;
                if (sb.Length > 0) sb.Append("; ");
                sb.Append(p.Name).Append('=').Append(Decode(p.Info, p.Value));
            }
            return sb.ToString();
        }
    }

    public static ProcessMitigationInfo QueryProcess(uint pid)
    {
        IntPtr h = IntPtr.Zero;
        try
        {
            h = OpenProcess(ProcessQueryLimitedInformation, false, pid);
            if (h == IntPtr.Zero)
                return new ProcessMitigationInfo(pid, "", Array.Empty<PolicyValue>(),
                    "access_denied(" + Marshal.GetLastWin32Error() + ") protected or other-user process");
            return QueryHandle(h, pid, pid.ToString());
        }
        catch (Exception ex)
        {
            return new ProcessMitigationInfo(pid, "", Array.Empty<PolicyValue>(), "fault:" + ex.GetType().Name);
        }
        finally
        {
            if (h != IntPtr.Zero) CloseHandle(h);
        }
    }

    public sealed record SweepResult(IReadOnlyList<ProcessMitigationInfo> Rows, int Denied, int Examined);

    /// <summary>
    /// Bounded, on-demand sweep for the console. Capped and single-pass: it must never turn
    /// into the startup-wide scan that froze this machine on 2026-10-15.
    ///
    /// Ordering matters for usefulness, not speed: an unelevated engine cannot open the
    /// session-0 / protected processes that Process.GetProcesses() happens to return first, so
    /// a naive "first N pids" sweep fills the whole budget with access-denied rows. Candidates
    /// are therefore ranked by "same session as the engine, newest first" and denied rows do
    /// not consume the budget.
    /// </summary>
    public static SweepResult SnapshotAll(int maxProcesses)
    {
        int cap = Math.Clamp(maxProcesses, 1, 96);
        var rows = new List<ProcessMitigationInfo>();
        int self = Environment.ProcessId;
        int mySession;
        try { mySession = System.Diagnostics.Process.GetCurrentProcess().SessionId; }
        catch { mySession = 1; }

        var candidates = new List<(uint Pid, long SortKey)>();
        System.Diagnostics.Process[] procs;
        try { procs = System.Diagnostics.Process.GetProcesses(); }
        catch { return new SweepResult(rows, 0, 0); }

        foreach (var p in procs)
        {
            try
            {
                uint pid = (uint)p.Id;
                if (pid == 0 || pid == 4) continue;
                long age;
                try { age = (DateTime.UtcNow - p.StartTime).Ticks; }
                catch { age = long.MaxValue; }
                int sameSession = 0;
                try { sameSession = p.SessionId == mySession ? 1 : 0; } catch { }
                // newest first inside the session group; cross-session entries sort last
                long sortKey = ((long)sameSession << 62) | (0x3FFF_FFFF_FFFF_FFFF - (age & 0x3FFF_FFFF_FFFF_FFFF));
                candidates.Add((pid, sortKey));
            }
            catch { }
            finally { try { p.Dispose(); } catch { } }
        }

        candidates.Sort((a, b) => b.SortKey.CompareTo(a.SortKey));
        if (candidates.Count > 400) candidates.RemoveRange(400, candidates.Count - 400);

        int denied = 0, ok = 0;
        foreach (var c in candidates)
        {
            if (ok >= cap || ok + denied >= cap + 24) break;
            ProcessMitigationInfo info;
            try { info = c.Pid == (uint)self ? QuerySelf() : QueryProcess(c.Pid); }
            catch { continue; }
            rows.Add(info);
            if (info.Error.Length > 0) denied++;
            else ok++;
        }
        return new SweepResult(rows, denied, candidates.Count);
    }

    private static ProcessMitigationInfo QueryHandle(IntPtr handle, uint pid, string tag)
    {
        string image = "";
        try
        {
            var sb = new StringBuilder(1024);
            int size = sb.Capacity;
            if (QueryFullProcessImageNameW(handle, 0, sb, ref size) && size > 0)
                image = sb.ToString(0, size);
        }
        catch { }
        if (image.Length == 0)
        {
            try { image = pid == 0 ? "(current process)" : "pid-" + pid; }
            catch { image = "unknown"; }
        }

        var values = new List<PolicyValue>();
        int errors = 0;
        foreach (var p in Policies)
        {
            uint buf = 0;
            bool ok;
            try { ok = GetProcessMitigationPolicy(handle, p.Id, ref buf, SizeOfUint); }
            catch (EntryPointNotFoundException) { continue; }
            if (!ok) { errors++; continue; }
            values.Add(new PolicyValue(p, p.Label, buf));
        }

        string error = errors > 0 && values.Count == 0 ? "query_unsupported" : "";
        return new ProcessMitigationInfo(pid, image, values, error);
    }

    // ── rollback guard ─────────────────────────────────────────────────────

    /// <summary>
    /// Flat key=value state file under ProgramData (same layout the quarantine store uses).
    /// AOT-safe: no serializer, and a corrupt file is treated as "no guard history".
    /// </summary>
    public static class HardeningGuard
    {
        private static readonly object Io = new();

        public static string FilePath
        {
            get
            {
                string root;
                try
                {
                    root = Path.Combine(
                        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
                        "NexusXDR");
                }
                catch { root = Path.Combine(Path.GetTempPath(), "NexusXDR"); }
                return Path.Combine(root, "hardening_guard.txt");
            }
        }

        public sealed class State
        {
            public bool Pending;      // ACG armed last run, healthy checkpoint never reached
            public bool AcgDisabled;  // latched off by the rollback guard
            public int Failures;      // runs that never reached the checkpoint
            public string LastDetail = "";
        }

        public static State Load()
        {
            var s = new State();
            try
            {
                lock (Io)
                {
                    if (!File.Exists(FilePath)) return s;
                    foreach (string line in File.ReadAllLines(FilePath))
                    {
                        int eq = line.IndexOf('=');
                        if (eq <= 0) continue;
                        string k = line.Substring(0, eq).Trim();
                        string v = line.Substring(eq + 1).Trim();
                        switch (k)
                        {
                            case "pending": s.Pending = v == "1"; break;
                            case "acg_off": s.AcgDisabled = v == "1"; break;
                            case "failures": int.TryParse(v, NumberStyles.Integer, CultureInfo.InvariantCulture, out int f); s.Failures = f; break;
                            case "detail": s.LastDetail = v; break;
                        }
                    }
                }
            }
            catch { }
            return s;
        }

        public static void Save(State s)
        {
            try
            {
                lock (Io)
                {
                    string? dir = Path.GetDirectoryName(FilePath);
                    if (dir != null) Directory.CreateDirectory(dir);
                    var sb = new StringBuilder();
                    sb.Append("pending=").Append(s.Pending ? 1 : 0).Append('\n');
                    sb.Append("acg_off=").Append(s.AcgDisabled ? 1 : 0).Append('\n');
                    sb.Append("failures=").Append(s.Failures).Append('\n');
                    sb.Append("detail=").Append(s.LastDetail.Replace('\n', ' ').Replace('\r', ' ')).Append('\n');
                    sb.Append("updated=").Append(DateTimeOffset.UtcNow.ToUnixTimeMilliseconds()).Append('\n');
                    File.WriteAllText(FilePath, sb.ToString());
                }
            }
            catch { }
        }

        public static void Delete()
        {
            try { lock (Io) { if (File.Exists(FilePath)) File.Delete(FilePath); } }
            catch { }
        }
    }
}
