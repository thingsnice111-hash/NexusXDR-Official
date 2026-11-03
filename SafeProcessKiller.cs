using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Threading;

namespace NexusAV.Engine;

/// <summary>
/// Reactive termination layer: the single place where Nexus actually kills an attacker.
/// The Storyteller computes a risk score; when the score crosses <see cref="KillScoreThreshold"/>
/// (and the DCA cross-verification proceeds), callers hand the attacker PID to
/// <see cref="Terminate"/>, which does a real children-first TerminateProcess tree kill.
///
/// Safety rails — this runs on a real daily-driver machine, so a mis-scored process must
/// never take the OS down with it:
///  - System-critical images (smss/csrss/wininit/winlogon/services/lsass/…) are NEVER killed;
///    that bluescreens Windows. Protection is path-aware: only the genuine copy in
///    System32/SysWOW64 is untouchable, so a malware named svchost.exe in %TEMP% stays killable.
///  - The engine process and its parent (the GUI) are never killed.
///  - BypassMode disables killing entirely.
///  - Per-PID rate limit: a burst of repeated events cannot become a kill storm.
///  - "Terminated" means OUR TerminateProcess on the root succeeded; a process that already
///    exited is reported as failed, never as killed.
/// </summary>
public static unsafe class SafeProcessKiller
{
    public const int KillScoreThreshold = 70;

    private const uint TerminateAccess = 0x0001;
    private const uint QueryLimitedAccess = 0x1000;
    private const uint SnapshotProcess = 0x00000002;

    private static uint _enginePid;
    private static uint _guiPid;

    private static readonly ConcurrentDictionary<uint, long> _recentKills = new();

    // Kill-storm fuse. A mis-scored rule must degrade the product to detection, not stall the
    // host: killing every process a bad rule matches produced respawn storms before. Crossing
    // this many terminations in a minute flips the engine to detect-only.
    private const int MaxKillsPerMinute = 12;
    private static readonly ConcurrentQueue<long> _killStamps = new();
    private static int _fuseTripped;
    private static long _fuseTrippedAt;
    private static int _fuseTrips;

    // The fuse must not stay latched forever — a single mis-scored rule would otherwise switch
    // protection off until a human notices. After this much quiet the fuse re-arms itself, but
    // only once: a second storm in the same run means the rule is still wrong, and from then on
    // only the operator can turn termination back on.
    private const long FuseCooldownMs = 5 * 60 * 1000;
    private const int MaxAutoRearms = 1;
    private static int _autoRearms;

    // Detect-only can be chosen by the operator or forced by the fuse. Only the fuse's own choice
    // is undone by an automatic re-arm; an operator who picked detect-only keeps it.
    private static int _fuseOwnsDetectOnly;

    // Halt (suspend) bookkeeping. Every pid we froze is remembered so it can be thawed from the
    // GUI, and so a freeze is never something the operator has to discover on their own.
    private const uint SuspendResumeAccess = 0x0800; // PROCESS_SUSPEND_RESUME
    private static readonly ConcurrentDictionary<uint, long> _frozen = new();

    // Bounded containment: a failed kill must not leave a process frozen forever. A suspended
    // innocent process is a false-positive disaster, so halts left behind by a refused kill are
    // thawed automatically after a cooldown unless the operator resumes them sooner.
    private const long AutoThawAfterFailedKillMs = 10 * 60 * 1000;
    private const long AutoThawCheckIntervalMs = 30_000;
    private static readonly ConcurrentDictionary<uint, long> _autoThaw = new();
    private static Timer? _autoThawTimer;

    // Never terminate these by image name. Path decides whether the name is real:
    // system32/syswow64 (and \Windows Defender\) copies are protected, copies elsewhere are not.
    private static readonly HashSet<string> SystemCriticalNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "system", "registry",
        "smss.exe", "csrss.exe", "wininit.exe", "winlogon.exe", "services.exe",
        "lsass.exe", "lsaiso.exe", "logonui.exe", "dwm.exe", "explorer.exe",
        "svchost.exe", "sihost.exe", "fontdrvhost.exe", "audiodg.exe",
        "conhost.exe", "taskhostw.exe", "wudfhost.exe", "spoolsv.exe",
        "searchindexer.exe", "shellexperiencehost.exe",
        "dllhost.exe", "runtimebroker.exe",
        "msmpeng.exe", "nissrv.exe", "mpdefendercoreservice.exe",
        "securityhealthservice.exe", "securityhealthsystray.exe", "securityhealthhost.exe"
    };

    /// <summary>Call once at engine startup with our own PID (protects it and the launching GUI).</summary>
    public static void Initialize(uint enginePid)
    {
        _enginePid = enginePid;
        _autoThawTimer = new Timer(_ => RunAutoThaw(), null, Timeout.Infinite, Timeout.Infinite);
        try
        {
            using var self = Process.GetCurrentProcess();
            if (NativeMethods.NtQueryInformationProcess(self.Handle, NativeMethods.ProcessBasicInformation,
                    out var pbi, Marshal.SizeOf<NativeMethods.PROCESS_BASIC_INFORMATION>(), out _) == 0)
                _guiPid = unchecked((uint)pbi.InheritedFromUniqueProcessId.ToInt64());
        }
        catch
        {
        }
    }

    /// <summary>
    /// Bounded proof of the response rails using only processes this test spawns itself.
    /// Returns 0 when every check passed.
    ///
    /// It deliberately never calls <see cref="Terminate"/> on a real system process: the
    /// protected-image rail is exercised as the pure function it is, because being wrong there
    /// would cost the machine instead of the test.
    /// </summary>
    public static int SelfTest()
    {
        int fail = 0;
        Initialize(unchecked((uint)Environment.ProcessId));

        Check("protected-image rail (System32 csrss/svchost protected, %TEMP% masquerade is not)", ref fail,
            IsProtectedImage(@"C:\Windows\System32\csrss.exe")
            && IsProtectedImage(@"C:\Windows\System32\svchost.exe")
            && !IsProtectedImage(@"C:\Users\someone\AppData\Local\Temp\svchost.exe"));
        Check("engine pid is never killed", ref fail, !Terminate(_enginePid, "selftest", KillScoreThreshold));
        Check("pid 4 (System) is never killed", ref fail, !Terminate(4, "selftest", KillScoreThreshold));

        using (Process? idle = SpawnVictim())
        {
            if (idle == null) { Console.WriteLine("[RESPONSE-SELFTEST] FAIL could not spawn a test child"); return 1; }
            uint idlePid = unchecked((uint)idle.Id);
            int previousMode = Volatile.Read(ref EngineState.DetectOnlyMode);
            Volatile.Write(ref EngineState.DetectOnlyMode, 1);
            bool acted = Terminate(idlePid, "selftest-detectonly", KillScoreThreshold);
            Volatile.Write(ref EngineState.DetectOnlyMode, previousMode);
            Check("detect-only refused the kill and halted nothing", ref fail,
                !acted && CreationTimeOf(idlePid) != 0 && !_frozen.ContainsKey(idlePid));
            try { if (!idle.HasExited) idle.Kill(true); } catch { }
        }

        using (Process? root = SpawnVictim())
        {
            if (root == null) { Console.WriteLine("[RESPONSE-SELFTEST] FAIL could not spawn a test child"); return 1; }
            uint rootPid = unchecked((uint)root.Id);
            Thread.Sleep(800); // let the child start so the tree is real
            // The tree-kill rail can only be proven with termination enabled; the operator's mode
            // is restored before this method returns.
            int previousMode = Volatile.Read(ref EngineState.DetectOnlyMode);
            Volatile.Write(ref EngineState.DetectOnlyMode, 0);
            List<uint> kids = GetDescendantPids(rootPid);
            bool killed = Terminate(rootPid, "selftest-tree", KillScoreThreshold);
            if (!FuseTripped) Volatile.Write(ref EngineState.DetectOnlyMode, previousMode);
            Thread.Sleep(300);

            // The root is checked through our own handle: a terminated process keeps its pid
            // allocated while any handle is open, and Process.Start holds one until disposed.
            bool rootExited = root.HasExited;
            bool kidsGone = true;
            foreach (uint k in kids)
                if (CreationTimeOf(k) != 0) kidsGone = false;

            Check($"tree kill: killed={killed} rootExited={rootExited} kidsGone={kidsGone} haltedLeft={_frozen.ContainsKey(rootPid)} children={kids.Count}", ref fail,
                killed && rootExited && kidsGone && !_frozen.ContainsKey(rootPid));
        }

        Console.WriteLine(fail == 0
            ? "[RESPONSE-SELFTEST] PASS every response rail behaved"
            : $"[RESPONSE-SELFTEST] FAIL {fail} check(s) failed");
        return fail == 0 ? 0 : 1;
    }

    /// <summary>A throwaway cmd.exe with a ping.exe child — the only processes the self-test touches.</summary>
    private static Process? SpawnVictim()
    {
        try
        {
            var psi = new ProcessStartInfo("cmd.exe", "/c ping -n 20 127.0.0.1 > nul")
            {
                UseShellExecute = false,
                CreateNoWindow = true
            };
            return Process.Start(psi);
        }
        catch { return null; }
    }

    private static void Check(string what, ref int fail, bool ok)
    {
        if (!ok) fail++;
        Console.WriteLine($"[RESPONSE-SELFTEST] {(ok ? "ok  " : "FAIL")} {what}");
    }

    /// <summary>
    /// Reactive kill of <paramref name="pid"/> (and its children). Returns true only when OUR
    /// TerminateProcess on the root succeeded. Never throws; every refusal is logged.
    /// </summary>
    public static bool Terminate(uint pid, string reason, int score)
    {
        try
        {
            if (pid == 0 || pid == 4) return false;
            if (Volatile.Read(ref EngineState.BypassMode) != 0) return false;
            if (pid == _enginePid) return false;
            MaybeRearmFuseAfterCooldown();
            if (Volatile.Read(ref EngineState.DetectOnlyMode) != 0)
            {
                // Checked before the per-PID dedupe so a detect-only pass does not burn the
                // cooldown slot the operator needs once they re-enable termination.
                Console.WriteLine($"[RESPONSE] detect-only mode — pid={pid} NOT killed, reason={reason}");
                EventBus.Status($"response_detect_only pid={pid} reason={reason}");
                return false;
            }
            if (pid == _guiPid)
            {
                Console.WriteLine($"[RESPONSE] refused pid={pid} — Nexus GUI process is never killed");
                EventBus.Status($"response_refused pid={pid} reason=gui_process");
                return false;
            }

            long now = Environment.TickCount64;
            if (_recentKills.TryGetValue(pid, out long prev) && now - prev < 5000) return false;
            _recentKills[pid] = now;

            string path = QueryImagePath(pid);
            if (path.Length == 0)
            {
                Console.WriteLine($"[RESPONSE] cannot identify pid={pid} (exited or access denied) — kill skipped, reason={reason}");
                EventBus.Status($"response_skipped pid={pid} reason=unidentified_target detail={reason}");
                return false;
            }

            if (IsProtectedImage(path))
            {
                Console.WriteLine($"[RESPONSE] refused pid={pid} img={BaseName(path)} — protected system image, never killed, reason={reason}");
                EventBus.Status($"response_refused pid={pid} img={BaseName(path)} reason=protected_system_image");
                return false;
            }

            // PID plus creation stamp is the identity. Capture it before we touch anything so a
            // recycle between the detection and this point is caught after the halt.
            long rootCt = CreationTimeOf(pid);
            if (rootCt == 0)
            {
                Console.WriteLine($"[RESPONSE] pid={pid} gone before response — kill skipped, reason={reason}");
                EventBus.Status($"response_skipped pid={pid} reason=pid_gone detail={reason}");
                return false;
            }

            var descendants = GetDescendantPids(pid);
            var descCt = new Dictionary<uint, long>(descendants.Count);
            foreach (uint d in descendants) descCt[d] = CreationTimeOf(d);

            // Halt before kill: freezing the attacker tree stops the damage in milliseconds and
            // one API call undoes it, so a wrong verdict costs a pause instead of a dead app.
            int halted = HaltTree(pid, descendants, reason);

            // If the stamp moved, whatever we froze is NOT the detected process: release and refuse.
            if (CreationTimeOf(pid) != rootCt)
            {
                Resume(pid);
                foreach (uint d in descendants) Resume(d);
                Console.WriteLine($"[RESPONSE] refused pid={pid} — pid identity changed mid-response (reuse), halt released, reason={reason}");
                EventBus.Status($"response_refused pid={pid} reason=pid_reused");
                return false;
            }

            int descendantsKilled = 0;
            for (int i = descendants.Count - 1; i >= 0; i--)
            {
                uint d = descendants[i];
                if (descCt.TryGetValue(d, out long c0) && c0 != 0 && CreationTimeOf(d) == c0 && KillOne(d))
                    descendantsKilled++;
            }

            bool rootKilled = false;
            for (int attempt = 0; attempt < 3 && !rootKilled; attempt++)
            {
                rootKilled = KillOne(pid);
                if (!rootKilled && attempt < 2) Thread.Sleep(40);
            }

            if (halted > 0) ReportFrozen(pid, descendants, rootKilled);

            Console.WriteLine(rootKilled
                ? $"[RESPONSE] killed pid={pid} img={BaseName(path)} score={score} children={descendantsKilled}/{descendants.Count} reason={reason}"
                : $"[RESPONSE] kill-failed pid={pid} img={BaseName(path)} score={score} halted={halted} reason={reason}");
            if (rootKilled) NoteKillAndCheckFuse(pid);
            else EventBus.Status($"response_kill_failed pid={pid} img={BaseName(path)} reason={reason}");
            return rootKilled;
        }
        catch
        {
            return false;
        }
    }

    /// <summary>
    /// Sliding-window kill counter. Crossing <see cref="MaxKillsPerMinute"/> in 60 s means a rule
    /// is mis-firing; flip the whole engine to detect-only and tell the operator instead of
    /// continuing to terminate processes.
    /// </summary>
    private static void NoteKillAndCheckFuse(uint pid)
    {
        long now = Environment.TickCount64;
        _killStamps.Enqueue(now);
        PruneKillWindow(now);

        int count = _killStamps.Count;
        if (count < MaxKillsPerMinute) return;
        if (Interlocked.Exchange(ref _fuseTripped, 1) != 0) return;

        int trips = Interlocked.Increment(ref _fuseTrips);
        Volatile.Write(ref _fuseTrippedAt, now);
        Volatile.Write(ref EngineState.DetectOnlyMode, 1);
        Volatile.Write(ref _fuseOwnsDetectOnly, 1);
        bool canRearm = Volatile.Read(ref _autoRearms) < MaxAutoRearms;
        Console.WriteLine($"[RESPONSE] KILL FUSE TRIPPED: {count} terminations in the last 60 s — response mode switched to DETECT-ONLY."
            + (canRearm
                ? $" Re-arms itself after {FuseCooldownMs / 60000} min without a kill; review the engine log before then."
                : " This is a repeat trip, so it stays off until you re-enable Terminate in the GUI."));
        EventBus.Detection("response", "high", "Response mode auto-disabled",
            $"Kill fuse tripped: {count} terminations within 60 s. A mis-scoring rule would otherwise stall the host, so killing is off"
            + (canRearm ? $" and re-arms automatically after {FuseCooldownMs / 60000} quiet minutes." : " until you re-enable it from the GUI."), pid);
        EventBus.Status($"response_kill_storm kills={count} window_s=60 trips={trips} auto_rearm={(canRearm ? 1 : 0)}");
    }

    private static void PruneKillWindow(long now)
    {
        while (_killStamps.TryPeek(out long oldest) && now - oldest > 60_000)
            _killStamps.TryDequeue(out _);
    }

    /// <summary>
    /// Releases the fuse latch once the storm has clearly passed. Without this a single mis-scored
    /// rule would leave the host permanently unprotected until somebody clicked in the GUI. It runs
    /// at most <see cref="MaxAutoRearms"/> time(s) per engine run: if the same rule storms again,
    /// the latch stays and only the operator can lift it.
    /// </summary>
    private static void MaybeRearmFuseAfterCooldown()
    {
        if (Volatile.Read(ref _fuseTripped) == 0) return;
        long trippedAt = Volatile.Read(ref _fuseTrippedAt);
        if (trippedAt == 0) return;
        long now = Environment.TickCount64;
        if (now - trippedAt < FuseCooldownMs) return;
        PruneKillWindow(now);
        if (!_killStamps.IsEmpty) return;
        if (Volatile.Read(ref _autoRearms) >= MaxAutoRearms) return;

        Interlocked.Increment(ref _autoRearms);
        ResetKillFuse();
        Console.WriteLine($"[RESPONSE] kill fuse re-armed after {FuseCooldownMs / 60000} min with no terminations — response mode is live again");
        EventBus.Status($"response_fuse_cooldown_rearmed cooldown_s={FuseCooldownMs / 1000} auto_rearms={Volatile.Read(ref _autoRearms)}");
    }

    /// <summary>Clears the fuse latch and, when the fuse was what forced detect-only, restores
    /// termination. An operator-chosen detect-only mode is left alone.</summary>
    public static void ResetKillFuse()
    {
        Volatile.Write(ref _fuseTripped, 0);
        Volatile.Write(ref _fuseTrippedAt, 0);
        while (_killStamps.TryDequeue(out _)) { }
        if (Interlocked.Exchange(ref _fuseOwnsDetectOnly, 0) != 0)
            Volatile.Write(ref EngineState.DetectOnlyMode, 0);
    }

    /// <summary>
    /// The operator picked the response mode explicitly, so the mode now belongs to them: an
    /// automatic fuse re-arm must never flip the engine back to terminating behind their back.
    /// </summary>
    public static void OperatorSetResponseMode(int detectOnly)
    {
        Volatile.Write(ref _fuseOwnsDetectOnly, 0);
        if (detectOnly == 0) ResetKillFuse();
    }

    /// <summary>True when the kill-rate fuse has tripped (surfaced in the GUI status line).</summary>
    public static bool FuseTripped => Volatile.Read(ref _fuseTripped) != 0;

    /// <summary>Pids currently frozen by a halt (pid -> tick when frozen). Exposed so the GUI can
    /// show exactly what is halted and offer a thaw.</summary>
    public static IReadOnlyDictionary<uint, long> FrozenPids => _frozen;

    /// <summary>
    /// Freezes the attacker and its descendants with NtSuspendProcess. Protected system images are
    /// never frozen (suspending csrss or services is a machine outage, not a mitigation), and an
    /// unidentified pid is never frozen. Returns how many processes are actually halted.
    /// </summary>
    private static int HaltTree(uint root, List<uint> descendants, string reason)
    {
        if (Volatile.Read(ref EngineState.BypassMode) != 0) return 0;

        int halted = 0;
        if (HaltOne(root)) halted++;
        foreach (uint d in descendants)
        {
            if (d == root) continue;
            string dpath = QueryImagePath(d);
            if (dpath.Length == 0 || IsProtectedImage(dpath)) continue;
            if (HaltOne(d)) halted++;
        }

        if (halted > 0)
        {
            Console.WriteLine($"[RESPONSE] halted pid={root} tree={halted} reason={reason}");
            EventBus.Status($"response_halt pid={root} halted={halted}");
            EventBus.Detection("response", "shield", "Attacker halted",
                $"{halted} process(es) frozen with NtSuspendProcess starting at pid {root} — reversible with Resume, nothing was deleted. {reason}", root);
        }
        return halted;
    }

    /// <summary>
    /// Reversible containment used by the signature-free file engine: freeze the process tree,
    /// delete nothing, kill nothing. A heuristic verdict that has never been corroborated at
    /// runtime does not justify destroying the operator's own work, so the strongest action this
    /// path can take is one NtResumeProcess away from undone.
    /// Returns how many processes were actually halted (0 = nothing was contained).
    /// </summary>
    public static int HaltOnly(uint pid, string reason)
    {
        try
        {
            if (pid == 0 || pid == 4 || pid == _enginePid || pid == _guiPid) return 0;
            if (Volatile.Read(ref EngineState.BypassMode) != 0) return 0;
            MaybeRearmFuseAfterCooldown();
            if (Volatile.Read(ref EngineState.DetectOnlyMode) != 0)
            {
                Console.WriteLine($"[RESPONSE] detect-only mode — halt skipped for pid={pid}, reason={reason}");
                EventBus.Status($"response_detect_only pid={pid} reason=zeroday_halt");
                return 0;
            }

            string path = QueryImagePath(pid);
            if (path.Length == 0)
            {
                EventBus.Status($"response_skipped pid={pid} reason=unidentified_target detail=zeroday_halt");
                return 0;
            }
            if (IsProtectedImage(path))
            {
                Console.WriteLine($"[RESPONSE] refused to halt pid={pid} img={BaseName(path)} — protected system image, reason={reason}");
                EventBus.Status($"response_refused pid={pid} img={BaseName(path)} reason=protected_system_image");
                return 0;
            }

            return HaltTree(pid, GetDescendantPids(pid), reason);
        }
        catch
        {
            return 0;
        }
    }

    /// <summary>Full image path of a pid, or "" when it has exited / is protected from us.</summary>
    public static string ImagePathOf(uint pid)
    {
        try { return QueryImagePath(pid); }
        catch { return string.Empty; }
    }

    private static bool HaltOne(uint pid)
    {
        if (pid == 0 || pid == 4 || pid == _enginePid || pid == _guiPid) return false;
        if (_frozen.ContainsKey(pid)) return true;
        IntPtr h = OpenProcess(SuspendResumeAccess, false, pid);
        if (h == IntPtr.Zero) return false;
        try
        {
            int status = NtSuspendProcess(h);
            if (status != 0) return false;
            _frozen[pid] = Environment.TickCount64;
            return true;
        }
        catch { return false; }
        finally { CloseHandle(h); }
    }

    /// <summary>
    /// Thaws one frozen pid. Called by the operator when a verdict turns out to be wrong — this is
    /// the reason halting is safer than killing.
    /// </summary>
    public static string Resume(uint pid)
    {
        if (!_frozen.TryGetValue(pid, out _)) return $"pid {pid} is not halted by Nexus";
        IntPtr h = OpenProcess(SuspendResumeAccess, false, pid);
        if (h == IntPtr.Zero)
        {
            _frozen.TryRemove(pid, out _);
            _autoThaw.TryRemove(pid, out _);
            return $"pid {pid} is gone (open denied) — dropped from the halted list";
        }
        try
        {
            int status = NtResumeProcess(h);
            if (status != 0) return $"NtResumeProcess failed for pid {pid}: 0x{status:X8} — it stays halted";
            _frozen.TryRemove(pid, out _);
            _autoThaw.TryRemove(pid, out _);
            EventBus.Status($"resume_ok pid={pid}");
            return $"pid {pid} resumed";
        }
        finally { CloseHandle(h); }
    }

    /// <summary>Thaws everything Nexus froze. Panic path: one command undoes all halts.</summary>
    public static int ThawAll()
    {
        int n = 0;
        foreach (uint pid in new List<uint>(_frozen.Keys))
        {
            Resume(pid);
            if (!_frozen.ContainsKey(pid)) n++;
        }
        return n;
    }

    private static void UntrackFrozen(uint pid) => _frozen.TryRemove(pid, out _);

    /// <summary>
    /// Reports what is still frozen after the kill attempt. When the root died, its children died
    /// with it and the list is already clean; when the kill failed, the attacker is alive but
    /// immobilised, and the operator must be told instead of left guessing.
    /// </summary>
    private static void ReportFrozen(uint root, List<uint> descendants, bool rootKilled)
    {
        if (!_frozen.TryGetValue(root, out _)) return;

        if (rootKilled)
        {
            // The root died, so nothing it froze can still matter; thaw the children so no
            // legitimate orphan is left suspended and invisible to the operator.
            UntrackFrozen(root);
            _autoThaw.TryRemove(root, out _);
            foreach (uint d in descendants)
                if (_frozen.TryGetValue(d, out _)) Resume(d);
            EventBus.Status($"response_halt_cleared pid={root} remaining={_frozen.Count}");
            return;
        }
        ScheduleAutoThaw(root, descendants);
        int still = _frozen.Count;
        Console.WriteLine($"[RESPONSE] pid={root} still halted (kill did not succeed), halted_total={still}");
        EventBus.Status($"response_held pid={root} halted_total={still}");
        EventBus.Detection("response", "high", "Attacker halted, kill refused",
            $"pid {root} could not be terminated but stays frozen ({still} process(es) halted). Use Resume in the GUI to thaw it, or fix the reason for the failed kill.", root);
    }

    /// <summary>
    /// Puts a deadline on containment that a failed kill left behind. A suspended process is
    /// reversible, but an unnoticed one is still a broken app on the operator's machine, so a halt
    /// nobody thawed and no kill finished is released by itself after
    /// <see cref="AutoThawAfterFailedKillMs"/>.
    /// </summary>
    private static void ScheduleAutoThaw(uint root, List<uint> descendants)
    {
        long deadline = Environment.TickCount64 + AutoThawAfterFailedKillMs;
        int armed = 0;
        if (_frozen.ContainsKey(root) && _autoThaw.TryAdd(root, deadline)) armed++;
        foreach (uint d in descendants)
            if (d != root && _frozen.ContainsKey(d) && _autoThaw.TryAdd(d, deadline)) armed++;
        if (armed == 0) return;

        _autoThawTimer?.Change(AutoThawCheckIntervalMs, AutoThawCheckIntervalMs);
        Console.WriteLine($"[RESPONSE] auto-thaw armed for {armed} halted pid(s) in {AutoThawAfterFailedKillMs / 60000} min");
        EventBus.Status($"response_auto_thaw_armed pid={root} count={armed} after_ms={AutoThawAfterFailedKillMs}");
    }

    private static void RunAutoThaw()
    {
        if (_autoThaw.IsEmpty) return;
        long now = Environment.TickCount64;
        foreach (KeyValuePair<uint, long> kv in _autoThaw)
        {
            if (now < kv.Value) continue;
            _autoThaw.TryRemove(kv.Key, out _);
            if (!_frozen.ContainsKey(kv.Key)) continue;
            string result = Resume(kv.Key);
            Console.WriteLine($"[RESPONSE] auto-thaw pid={kv.Key} after a failed kill — containment is bounded, not permanent ({result})");
            EventBus.Status($"response_auto_thaw pid={kv.Key} remaining={_frozen.Count}");
        }
        if (_autoThaw.IsEmpty) _autoThawTimer?.Change(Timeout.Infinite, Timeout.Infinite);
    }


    /// <summary>
    /// True only for the genuine system copy of a critical image. A file merely NAMED
    /// svchost.exe outside System32/SysWOW64 (classic masquerade) is deliberately NOT protected.
    /// </summary>
    public static bool IsProtectedImage(string path)
    {
        if (string.IsNullOrEmpty(path)) return false;
        if (!SystemCriticalNames.Contains(BaseName(path))) return false;
        string lower = path.ToLowerInvariant();
        return lower.Contains("\\windows\\system32\\")
            || lower.Contains("\\windows\\syswow64\\")
            || lower.EndsWith("\\windows\\explorer.exe")
            || lower.Contains("\\windows defender\\");
    }

    private static string BaseName(string path)
    {
        int i = path.LastIndexOf('\\');
        return i >= 0 ? path.Substring(i + 1) : path;
    }

    private static string QueryImagePath(uint pid)
    {
        IntPtr h = OpenProcess(QueryLimitedAccess, false, pid);
        if (h == IntPtr.Zero) return string.Empty;
        try
        {
            int cap = 1024;
            char* buf = stackalloc char[cap];
            uint len = (uint)cap;
            if (QueryFullProcessImageNameW(h, 0, buf, ref len) && len > 0)
                return new string(buf, 0, (int)len);
            return string.Empty;
        }
        finally { CloseHandle(h); }
    }

    private static bool KillOne(uint pid)
    {
        if (pid == 0 || pid == 4 || pid == _enginePid) return false;
        IntPtr h = OpenProcess(TerminateAccess, false, pid);
        if (h == IntPtr.Zero) return false;
        try { return TerminateProcess(h, 1); }
        catch { return false; }
        finally { CloseHandle(h); }
    }

    private static List<uint> GetDescendantPids(uint root)
    {
        var result = new List<uint>();
        IntPtr snap = CreateToolhelp32Snapshot(SnapshotProcess, 0);
        if (snap == IntPtr.Zero || snap == new IntPtr(-1)) return result;
        try
        {
            var byParent = new Dictionary<uint, List<uint>>();
            var entry = new ProcessEntry32W();
            entry.dwSize = (uint)Marshal.SizeOf<ProcessEntry32W>();
            if (Process32First(snap, ref entry))
            {
                do
                {
                    uint p = entry.th32ProcessID;
                    uint pp = (uint)entry.th32ParentProcessID;
                    if (p != 0 && p != pp)
                    {
                        if (!byParent.TryGetValue(pp, out var list)) byParent[pp] = list = new List<uint>();
                        list.Add(p);
                    }
                } while (Process32Next(snap, ref entry));
            }

            var queue = new Queue<uint>();
            queue.Enqueue(root);
            while (queue.Count > 0 && result.Count < 512)
            {
                uint cur = queue.Dequeue();
                if (!byParent.TryGetValue(cur, out var kids)) continue;
                foreach (uint k in kids)
                {
                    if (k == root || k == _enginePid || k == _guiPid) continue;
                    result.Add(k);
                    queue.Enqueue(k);
                }
            }
        }
        finally { CloseHandle(snap); }
        return result;
    }

    private struct ProcessEntry32W
    {
        public uint dwSize;
        public uint cntUsage;
        public uint th32ProcessID;
        public IntPtr th32DefaultHeapID;
        public uint th32ModuleID;
        public uint cntThreads;
        public uint th32ParentProcessID;
        public int pcPriClassBase;
        public uint dwFlags;
        public fixed char szExeFile[260];
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr CreateToolhelp32Snapshot(uint flags, uint processId);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr handle);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool Process32First(IntPtr snapshot, ref ProcessEntry32W entry);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool Process32Next(IntPtr snapshot, ref ProcessEntry32W entry);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenProcess(uint access, bool inherit, uint processId);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool TerminateProcess(IntPtr process, uint exitCode);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool QueryFullProcessImageNameW(IntPtr process, uint flags, char* exeName, ref uint size);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool GetProcessTimes(IntPtr process, out long creation, out long exit, out long kernel, out long user);

    /// <summary>
    /// 100 ns creation stamp of a process, or 0 when it is gone or unopenable. PID plus creation
    /// time is the only reliable identity: bare PIDs are recycled within seconds.
    /// </summary>
    private static long CreationTimeOf(uint pid)
    {
        IntPtr h = OpenProcess(QueryLimitedAccess, false, pid);
        if (h == IntPtr.Zero) return 0;
        try
        {
            return GetProcessTimes(h, out long ct, out _, out _, out _) ? ct : 0;
        }
        finally { CloseHandle(h); }
    }

    [DllImport("ntdll.dll")]
    private static extern int NtSuspendProcess(IntPtr process);

    [DllImport("ntdll.dll")]
    private static extern int NtResumeProcess(IntPtr process);
}
