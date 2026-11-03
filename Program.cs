using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.IO.MemoryMappedFiles;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Threading;
using Microsoft.Win32.SafeHandles;
using NexusAV.Engine;

unsafe
{
    const int EXIT_OK = 0;
    const int EXIT_INIT_FAIL = 3;
    const string RINGBUFFER_SECTION = "Global\\NexusAVRingBuffer";
    const long RINGBUFFER_CAPACITY = 4 * 1024 * 1024;
    const uint RINGBUFFER_EVENT_COUNT = 100_000;

    bool testShutdown = args.Contains("--test-shutdown", StringComparer.Ordinal);
    bool skipShield = args.Contains("--no-shield", StringComparer.Ordinal);
    bool noHarden = args.Contains("--no-harden", StringComparer.Ordinal);
    bool noAcg = args.Contains("--no-acg", StringComparer.Ordinal);
    bool forceAcg = args.Contains("--force-acg", StringComparer.Ordinal);

    // Headless pass/fail check for the keep-alive packet crypto: sign -> verify must hold,
    // tamper and wrong-key must fail. Exits before any module starts.
    if (args.Contains("--selftest-ka", StringComparer.Ordinal))
    {
        bool kaOk = KeepAliveCrypto.SelfTest();
        Console.WriteLine(kaOk
            ? "[KA-SELFTEST] PASS sign->verify=true tamper->false wrong-key->false"
            : "[KA-SELFTEST] FAIL keep-alive packet crypto is broken");
        return kaOk ? 0 : 1;
    }

    // Headless Wi-Fi parse check: prints the decoded visible networks (log-only, no action).
    if (args.Contains("--selftest-wifi", StringComparer.Ordinal))
    {
        WifiSeekerC2Shield.SelfTestWlan();
        return 0;
    }

    // Headless response-rail check: spawns its own throwaway cmd/ping pair and proves the halt,
    // tree-kill, detect-only and protected-image rails. Touches no process it did not create.
    if (args.Contains("--selftest-response", StringComparer.Ordinal))
        return SafeProcessKiller.SelfTest();

    // Headless Authenticode check: a Microsoft catalog file must classify as MicrosoftSigned and
    // our own unsigned DLL must not.
    if (args.Contains("--selftest-sig", StringComparer.Ordinal))
        return WinTrust.SelfTest();

    // Installed before anything else logs: every engine line is tee'd to a rolling file so a run
    // where something was "detected but not blocked" can be diagnosed after the GUI is closed.
    EngineLog.Install();
    if (EngineLog.FilePath.Length > 0)
        Console.WriteLine($"[LOG] engine output persisted to {EngineLog.FilePath}");
    else
        Console.WriteLine("[LOG] file logging unavailable (no writable log directory) — console only");

    // Arm our own exploit mitigations before any module starts working. ACG is the only
    // irreversible one: it is refused up front while coreclr.dll is loaded (a JIT process cannot
    // generate code under ProhibitDynamicCode — measured, it exits 0xE0434352), and when it is
    // armed deliberately it runs behind a pending-checkpoint marker, so a death before the init
    // checkpoint makes the next start latch it off.
    ProcessMitigations.SelfHardeningResult hardening =
        ProcessMitigations.RunStartupHardening(noHarden, noAcg, forceAcg);
    Console.WriteLine($"[HARDEN] applied={hardening.Applied} acg={hardening.AcgSource} :: {hardening.Detail}");
    Console.WriteLine("[HARDEN] guard: " + hardening.Guard);
    foreach (string e in hardening.Enabled) Console.WriteLine("[HARDEN] enforced " + e);
    foreach (string f in hardening.Failed) Console.WriteLine("[HARDEN] refused " + f);
    EventBus.HardenStatus(hardening.AcgRequested, hardening.AcgActive, hardening.AcgSource, hardening.Detail);

    CommandReader? commandReader = null;
    Thread? eventPumpThread = null;

    FactChecker? factChecker = null;
    Storyteller? storyteller = null;
    DcaEngine? dcaEngine = null;
    MacroSmartHub? macroSmartHub = null;
    MemoryMappedFile? ringSection = null;
    MemoryMappedViewAccessor? ringView = null;
    byte* basePointer = null;
    NexusKeepAliveMonitor? kaMonitor = null;
    TpmValidationEngine? tpmEngine = null;
    SelfHealingShield? shield = null;
    EtwSubscriber? etwSubscriber = null;
    VirusTotalScanner? virusTotalScanner = null;
    QuarantineManager? quarantineManager = null;
    RealtimeScanner? realtimeScanner = null;
    BootkitScanner? bootkitScanner = null;
    
    // NEW: User-mode protection components (replacing kernel driver)
    UserModeProcessProtection? userModeProcessProtection = null;
    UserModeRegistryProtection? userModeRegistryProtection = null;
    UserModeFileSystemProtection? userModeFileSystemProtection = null;
    UserModeNetworkFilter? userModeNetworkFilter = null;
    UserModeSelfDefense? userModeSelfDefense = null;
    InjectionTracker? injectionTracker = null;
    ActiveGuardian? activeGuardian = null;
    StorytellerStable? storyFeed = null;
    SasBehaviorEngine? sasEngine = null;
    UsbDeviceGuard? usbGuard = null;
    UserModeMemoryIntegrityMonitor? memoryIntegrity = null;
    PersistenceGuard? persistenceGuard = null;
    ScriptGuard? scriptGuard = null;
    ZeroDayEngine? zeroDayEngine = null;
    MystralBridgeServer? mystralBridge = null;
    WhitelistManager? whitelistManager = null;
    FingerprintStore? fingerprintStore = null;
    
    byte[] rootTrustKey = new byte[32];
    Thread? decayThread = null;
    Thread? confidenceWriterThread = null;

    static bool TryResolveRealPpid(uint pid, out uint actualPpid)
    {
        actualPpid = 0;
        if (pid == 0 || pid == 4) return false;
        try
        {
            using var proc = Process.GetProcessById((int)pid);
            var hr = NativeMethods.NtQueryInformationProcess(proc.Handle, NativeMethods.ProcessBasicInformation, out var pbi, Marshal.SizeOf<NativeMethods.PROCESS_BASIC_INFORMATION>(), out _);
            if (hr == 0)
            {
                actualPpid = (uint)pbi.InheritedFromUniqueProcessId;
                return true;
            }
        } catch { }
        return false;
    }

    static uint ComputeHmacKaResponse(byte[] rootKey, uint challenge)
    {
        using var hmac = new HMACSHA256(rootKey);
        byte[] msg = BitConverter.GetBytes(challenge);
        byte[] digest = hmac.ComputeHash(msg);
        return BitConverter.ToUInt32(digest, 0);
    }

    try
    {
        factChecker = new FactChecker(OnLbrAnomaly);
        storyteller = new Storyteller();
        storyFeed = new StorytellerStable(storyteller);
        EventBus.StoryFeed = storyFeed; // every Detection/Alert/Guard/Quarantine becomes a story episode
        dcaEngine = new DcaEngine(storyteller);
        macroSmartHub = new MacroSmartHub(dcaEngine);
        macroSmartHub.Start();

        // RuntimeFeature.IsDynamicCodeSupported is folded from the PublishAot project property, so
        // it claims "AOT" even for this framework-dependent build. coreclr.dll in the module list is
        // the only honest answer, and it also decides whether ACG can be armed at all.
        bool jitBacked = ProcessMitigations.RunsOnJitRuntime;
        Console.Title = "NexusAV.Engine (user-mode only" + (jitBacked ? " - CoreCLR JIT" : " - Native AOT") + ")";
        Console.WriteLine($"[NexusAV.Engine] Starting USER-MODE ONLY architecture (pid={Environment.ProcessId}, runtime={(jitBacked ? "CoreCLR/JIT" : "native-AOT")})");
        Console.WriteLine("[NexusAV.Engine] NO KERNEL DRIVER REQUIRED - All protections implemented in user-mode");

        // Microsoft-Windows-Threat-Intelligence refuses to enable (0x80070005) unless
        // SeDebugPrivilege is ENABLED in our token — .NET leaves it disabled even when
        // elevated. Must run before any ETW session is created.
        if (PrivilegeEnabler.TryEnableSeDebugPrivilege())
        {
            Console.WriteLine("[INIT] SeDebugPrivilege enabled — Threat-Intelligence ETW provider can start");
        }
        else
        {
            Console.WriteLine("[INIT] SeDebugPrivilege NOT enabled (run the engine elevated). Threat-Intelligence provider will be denied; Kernel-Audit-API-Calls fallback still applies.");
        }

        if (!testShutdown)
        {
            // Initialize shared memory for inter-process communication
            ringSection = KernelBridge.OpenRingBufferSection(RINGBUFFER_SECTION, RINGBUFFER_CAPACITY);
            ringView = ringSection.CreateViewAccessor(0, RINGBUFFER_CAPACITY, MemoryMappedFileAccess.ReadWrite);
            byte* ptrTmp = null;
            ringView.SafeMemoryMappedViewHandle.AcquirePointer(ref ptrTmp);
            basePointer = ptrTmp;
            InitRingBuffer((nint)basePointer, RINGBUFFER_EVENT_COUNT);

            // User-configured path exceptions — independent of the shield so the list stays
            // manageable even when the engine runs with --no-shield.
            whitelistManager = new WhitelistManager();
            Console.WriteLine($"[WHITELIST] Loaded {whitelistManager.Count} user-configured path(s)");

            // Known-bad file identities (sha256 + import/section/fuzzy hashes). Also independent of
            // the shield: blocking a confirmed identity must not depend on the hardening path.
            fingerprintStore = new FingerprintStore();
            if (dcaEngine != null) dcaEngine.Fingerprints = fingerprintStore;
            Console.WriteLine($"[FP] Loaded {fingerprintStore.Count} known-bad fingerprint(s) from {fingerprintStore.FilePath}");

            if (!skipShield)
            {
                uint enginePid = unchecked((uint)Environment.ProcessId);
                ulong bootSeed = (ulong)(Environment.TickCount64 ^ ((long)enginePid << 8));
                for (int i = 0; i < 32; i++) rootTrustKey[i] = (byte)(((bootSeed >> ((i & 7) * 8)) & 0xFF) ^ (enginePid >> ((i * 3) & 24)) ^ 0x5Au);
                
                // Initialize Keep-Alive Monitor
                kaMonitor = new NexusKeepAliveMonitor(enginePid, bootSeed, 1000, 3, (state, pid, ch, ts) =>
                {
                    Console.WriteLine($"[KA-ALERT] pid={pid} state={state} challenge=0x{ch:X8} ts={ts}");
                });
                
                // Initialize TPM Validation Engine
                tpmEngine = new TpmValidationEngine();
                bool tpmOk = tpmEngine.ProbeAndInitialize();
                Console.WriteLine($"[PRE-BOOT] TPM validation engine ready={tpmOk}");
                
                // Initialize Self-Healing Shield (user-mode only)
                shield = new SelfHealingShield(rootTrustKey, tpmEngine, storyteller, dcaEngine, null);
                bool bootOk = shield.RunPreBootScan();
                int telemetry = shield.FlushEarlyTelemetry();
                Console.WriteLine($"[PRE-BOOT] scan complete: ok={bootOk} early_telemetry_records={telemetry}");
                
                kaMonitor.Start();
                shield.StartShield(kaMonitor, enginePid, phase =>
                {
                    Console.WriteLine($"[SHIELD-PHASE] -> {phase}");
                });

                // Initialize VirusTotal and Realtime Scanner
                virusTotalScanner = new VirusTotalScanner();
                dcaEngine.Vt = virusTotalScanner;
                quarantineManager = new QuarantineManager();
                realtimeScanner = new RealtimeScanner(virusTotalScanner, quarantineManager, whitelistManager);
                realtimeScanner.Fingerprints = fingerprintStore;
                realtimeScanner.OnKnownBadBlocked += (path, mc, tot, detail) =>
                {
                    Console.WriteLine($"[KNOWN-BAD] {path} :: {detail}");
                    EventBus.Detection("malware", "high", "Known-bad file blocked",
                        $"{Path.GetFileName(path)} — {detail}. The file was quarantined and every process running it was frozen; nothing was deleted.", 0);
                    EventBus.Status($"knownbad_blocked path={path.Replace(' ', '_')} vt={mc}/{tot}");
                };
                realtimeScanner.OnFingerprintHit += (path, kind, sha, note) =>
                {
                    Console.WriteLine($"[FP-HIT] {kind} {sha[..Math.Min(16, sha.Length)]} :: {path}");
                    EventBus.Detection("malware", kind == "exact" ? "high" : "medium", "Known-bad fingerprint match",
                        $"{Path.GetFileName(path)} matches a recorded known-bad identity ({kind}, sha256 {sha[..Math.Min(16, sha.Length)]}…). {(kind == "exact" ? "Quarantined and frozen." : "Reported only — the weaker tiers never act on their own.")}", 0);
                    EventBus.FpEntry("match", sha, "", kind, note, path);
                };
                realtimeScanner.OnDisputedVerdict += (path, mc, tot, score, signals) =>
                {
                    Console.WriteLine($"[DISPUTED] {path} vt={mc}/{tot} local={score}");
                    EventBus.Detection("malware", "medium", "Cloud verdict held, not acted on",
                        $"{Path.GetFileName(path)} — {mc}/{tot} engines flagged it, which is below the {RealtimeScanner.ProbableEngineThreshold}-engine bar. Local structure score {score}: {signals}. Nothing was quarantined; the file stays where it is until a second source agrees.", 0);
                    EventBus.Status($"disputed_verdict path={path.Replace(' ', '_')} vt={mc}/{tot} local_score={score}");
                };
                realtimeScanner.OnScanComplete += (path, result) =>
                {
                    Console.WriteLine($"[VT] Scanned {Path.GetFileName(path)}: {result.MaliciousCount}/{result.TotalEngines} malicious{(result.IsMalicious ? " - THREAT!" : "")}");
                    EventBus.Scan(path, result.MaliciousCount, result.TotalEngines, result.DetectionNames, result.IsMalicious, result.ErrorMessage);
                };
                realtimeScanner.OnThreatDetected += (path, threat) =>
                {
                    Console.WriteLine($"[VT-ALERT] Threat detected: {path} - {threat}");
                    EventBus.Detection("malware", "shield", "Malware detected", $"{path} — {threat}", 0);
                };
                realtimeScanner.OnQuarantineAction += (path, action) =>
                {
                    EventBus.Quarantine(path, path, "quarantined", action, "");
                };
                realtimeScanner.Start();
                Console.WriteLine("[VT] VirusTotal scanner and realtime protection initialized");

                // THE THIRD ENGINE — signature-free analysis of files the cloud cannot judge.
                zeroDayEngine = new ZeroDayEngine();
                zeroDayEngine.Whitelist = whitelistManager;
                zeroDayEngine.Fingerprints = fingerprintStore;
                realtimeScanner.LocalAnalyzer = path => zeroDayEngine.Analyze(path);
                realtimeScanner.OnZeroDayVerdict += (path, score, signals) =>
                {
                    EventBus.Detection("malware", score >= ZeroDayEngine.BlockScoreThreshold ? "high" : "medium",
                        "Unknown file judged locally",
                        $"{Path.GetFileName(path)} has no cloud verdict, so its structure was analysed: score {score} — {signals}. It is flagged now and frozen the moment it executes.",
                        0);
                    EventBus.Status($"zeroday_file path={path.Replace(' ', '_')} score={score}");
                };
                zeroDayEngine.Start();

                // Initialize NEW User-Mode Protection Components
                
                // 1. User-Mode Process Protection (replaces ObRegisterCallbacks)
                userModeProcessProtection = new UserModeProcessProtection();
                userModeProcessProtection.OnTerminationAttempt += (target, attacker, method) =>
                {
                    Console.WriteLine($"[PROCESS-PROT] Termination attempt: target={target} attacker={attacker} method={method}");
                    EventBus.Detection("process", "audit", "Process termination attempt detected", $"target pid={target} attacker pid={attacker} via {method} (observed, not prevented)", attacker);
                };
                userModeProcessProtection.OnHandleViolation += (target, violator, access) =>
                {
                    Console.WriteLine($"[PROCESS-PROT] Handle violation: target={target} violator={violator} access=0x{access:X}");
                    EventBus.Detection("process", "audit", "Handle access violation", $"target pid={target} violator pid={violator} access=0x{access:X}", violator);
                };
                userModeProcessProtection.ProtectProcess(enginePid, "NexusAV.Engine");
                userModeProcessProtection.Start();
                Console.WriteLine("[PROCESS-PROT] User-mode process protection initialized (replaces ObRegisterCallbacks)");

                // 2. User-Mode Registry Protection (replaces CmRegisterCallbackEx)
                userModeRegistryProtection = new UserModeRegistryProtection();
                userModeRegistryProtection.OnRegistryWriteAttempt += (key, value, pid, name) =>
                {
                    Console.WriteLine($"[REGISTRY-PROT] Write attempt: key={key} value={value} pid={pid} name={name}");
                    EventBus.Detection("registry", "audit", "Registry write to protected key", $"pid={pid} ({name}) -> {key}\\{value}", pid);
                };
                userModeRegistryProtection.Start();
                Console.WriteLine("[REGISTRY-PROT] User-mode registry protection initialized (replaces CmRegisterCallbackEx)");

                // 3. User-Mode File System Protection (replaces minifilter)
                userModeFileSystemProtection = new UserModeFileSystemProtection();
                userModeFileSystemProtection.OnFileOperationAttempt += (path, op, pid, name) =>
                {
                    Console.WriteLine($"[FILESYSTEM-PROT] Operation: path={path} op={op} pid={pid} name={name}");
                    EventBus.Detection("filesystem", "audit", "Protected file system operation", $"{op} by pid={pid} ({name}) on {path}", pid);
                };
                userModeFileSystemProtection.Start();
                Console.WriteLine("[FILESYSTEM-PROT] User-mode file system protection initialized (replaces minifilter)");

                // 4. User-Mode Network Filter (replaces WFP)
                userModeNetworkFilter = new UserModeNetworkFilter();
                userModeNetworkFilter.OnSuspiciousConnection += (pid, ip, proto) =>
                {
                    Console.WriteLine($"[NETWORK-FILTER] Suspicious: pid={pid} ip={ip} proto={proto}");
                    EventBus.Detection("network", "audit", "Suspicious outbound connection", $"pid={pid} -> {ip} ({proto})", pid);
                };
                userModeNetworkFilter.OnConnectionBlocked += (pid, ip) =>
                {
                    Console.WriteLine($"[NETWORK-FILTER] Blocked: pid={pid} ip={ip}");
                    EventBus.Detection("network", "shield", "Connection blocked", $"pid={pid} blocked from {ip}", pid);
                };
                userModeNetworkFilter.Start();
                Console.WriteLine("[NETWORK-FILTER] User-mode network filtering initialized (replaces WFP)");

                // 5. User-Mode Self-Defense (enhanced)
                userModeSelfDefense = new UserModeSelfDefense(enginePid);
                userModeSelfDefense.OnDefenseTriggered += (message) =>
                {
                    Console.WriteLine($"[SELF-DEFENSE] {message}");
                    EventBus.Detection("selfdefense", "shield", "Self-defense triggered", message, enginePid);
                };
                userModeSelfDefense.OnSuspiciousProcessDetected += (pid, name) =>
                {
                    Console.WriteLine($"[SELF-DEFENSE] Suspicious process: pid={pid} name={name}");
                    EventBus.Detection("selfdefense", "audit", "Suspicious process near protected target", $"pid={pid} ({name})", pid);
                };
                userModeSelfDefense.Start();
                Console.WriteLine("[SELF-DEFENSE] Enhanced user-mode self-defense initialized");

                // 6. Injection attempt registry — records what ETW detectors report, blocks nothing
                injectionTracker = new InjectionTracker();
                injectionTracker.OnInjectionAttempt += (src, dst, method) =>
                {
                    Console.WriteLine($"[INJECT-TRACKER] Attempt: src={src} dst={dst} method={method}");
                    EventBus.Detection("injection", "audit", "Process injection attempt", $"pid={src} -> pid={dst} via {method}", src);
                };
                injectionTracker.OnInjectionBlocked += (pid, method) =>
                {
                    Console.WriteLine($"[INJECT-TRACKER] Blocked: pid={pid} method={method}");
                    EventBus.Detection("injection", "shield", "Process injection blocked", $"pid={pid} method={method}", pid);
                };
                injectionTracker.Start();
                Console.WriteLine("[INJECT-TRACKER] injection attempt registry initialized (records only, no blocking)");

                // Initialize Bootkit Scanner (user-mode only - no driver required)
                bootkitScanner = new BootkitScanner();
                Task.Run(() =>
                {
                    Thread.Sleep(2000);
                    bootkitScanner.ScanAllDisksAsync().GetAwaiter().GetResult();
                });
                Console.WriteLine("[BOOTKIT] User-mode disk integrity scanner initialized (no driver required)");
            }

            // ── Active Guardian: 250 ms user-mode command-line / process guard ────────
            SafeProcessKiller.Initialize(unchecked((uint)Environment.ProcessId));
            activeGuardian = new ActiveGuardian(storyteller!, unchecked((uint)Environment.ProcessId));
            activeGuardian.Start();
            Console.WriteLine("[GUARDIAN] Active Guardian started (250 ms new-process watch + 1 s snapshot backstop + ETW feed when elevated)");

            // ── SAS: signature-free behavior engine (3D activity trajectories) ────────
            sasEngine = new SasBehaviorEngine(storyteller!, storyFeed!);
            sasEngine.Start();
            Console.WriteLine("[SAS] Behavior engine started - signature-free trajectory analysis (2 s sampling)");

            // ── Per-device USB storage guard (CfgMgr32; auto-reverts on engine stop) ──
            usbGuard = new UsbDeviceGuard(storyFeed!);
            usbGuard.Start();
            Console.WriteLine("[USB] Per-device USB storage guard started (blocks never outlive the engine)");

            // ── Memory integrity monitor (read-only; replaces the kernel-LBR fiction) ─
            memoryIntegrity = new UserModeMemoryIntegrityMonitor(storyteller!, storyFeed!);
            memoryIntegrity.Start();
            Console.WriteLine("[MEM-VERIFY] Memory integrity monitor started (30 s cadence, read-only)");

            // ── Persistence watcher: Task Scheduler + Startup folders ───────────────
            // Run/RunOnce keys are already covered by UserModeRegistryProtection.
            persistenceGuard = new PersistenceGuard();
            persistenceGuard.Start();
            Console.WriteLine("[PERSIST] Persistence watcher started (Scheduled Tasks dir + Startup folders)");

            // ETW Subscriber for cross-process API monitoring
            scriptGuard = new ScriptGuard(storyteller!);
            scriptGuard.Start();
            Console.WriteLine("[SCRIPTGUARD] Content-level script analyzer started (awaits the AMSI/PowerShell ETW feed)");

            etwSubscriber = new EtwSubscriber(ev =>
            {
                string api = ev.AllocationType switch
                {
                    1 => "VirtualAllocEx",
                    3 => "SetThreadContext",
                    4 => "MapViewOfSection",
                    _ => "WriteProcessMemory"
                };
                var (score, allow, audit, act) = storyteller.ReportEtwCrossProcessApi(api, ev.CallerPid, ev.TargetPid, ev.AllocationBase, ev.Protect);
                Console.WriteLine($"[ETW][{api}] caller={ev.CallerPid} target={ev.TargetPid} base=0x{ev.AllocationBase:X} prot=0x{ev.Protect:X} score={score}{(allow ? " [ALLOWLIST]" : "")}{(audit ? " [AUDIT]" : "")}{(act ? " [SHIELD]" : "")}");
                if (act)
                {
                    var verdict = dcaEngine!.VerifyBeforeAct(ev.CallerPid);
                    EventBus.Alert(ev.CallerPid, $"cross-process {api}", score, verdict.Proceed ? "shield" : "veto",
                        verdict.Proceed
                            ? $"SHIELD: {api} caller={ev.CallerPid} target={ev.TargetPid} :: {verdict.Reason}"
                            : $"HELD: {api} caller={ev.CallerPid} target={ev.TargetPid} :: {verdict.Reason}");
                    if (verdict.Proceed)
                    {
                        // Reactive termination: the Storyteller score crossed the kill
                        // threshold and DCA verified — take the attacker PID and kill its
                        // tree now. (User-mode limitation: the injected bytes are already
                        // in memory, but the hostile process dies within milliseconds.)
                        if (score >= SafeProcessKiller.KillScoreThreshold &&
                            SafeProcessKiller.Terminate(ev.CallerPid, $"cross-process {api} -> pid {ev.TargetPid} :: {verdict.Reason}", score))
                        {
                            EventBus.Detection("response", "shield", "Attacker terminated",
                                $"pid {ev.CallerPid} killed at score {score} — {api} into pid {ev.TargetPid} :: {verdict.Reason}", ev.CallerPid);
                        }

                        // Real containment: cut the hostile image's outbound network via the
                        // dynamic-session WFP block (filters vanish when the engine exits).
                        var cn = storyteller!.GetOrAdd(ev.CallerPid, 0, "unknown.exe");
                        if (!string.IsNullOrEmpty(cn.FullImagePath))
                        {
                            string? werr = WfpBlocker.BlockImage(cn.FullImagePath);
                            Console.WriteLine(werr == null
                                ? $"[WFP] Outbound containment active for {cn.ImageName} ({cn.FullImagePath})"
                                : $"[WFP] Containment unavailable: {werr}");
                            if (werr == null)
                                EventBus.Detection("network", "shield", "Network containment applied",
                                    $"{cn.ImageName} (pid {ev.CallerPid}) outbound connects blocked — WFP dynamic session", ev.CallerPid);
                        }
                    }
                }
                else if (audit)
                {
                    EventBus.Alert(ev.CallerPid, $"cross-process {api}", score, "audit", $"AUDIT: {api} caller={ev.CallerPid} target={ev.TargetPid}");
                }
            },
            onProcessStart: (pid, parent, img) =>
            {
                storyteller!.ReportProcessStart(pid, parent, img);
                storyFeed!.AddProcessStart(pid, parent, img);
                if (parent != 0 && parent != 4 && TryResolveRealPpid(pid, out uint actualPpid))
                    storyteller.DetectPpidSpoofing(pid, parent, actualPpid);
                if (ActiveGuardian.IsGuardedImageName(img))
                    activeGuardian.EnqueueSuspect(pid, img);
            },
            onScriptContent: (pid, source, content) => scriptGuard!.Submit(pid, source, content));
            if (!etwSubscriber.Start() && etwSubscriber.LastError != null)
                Console.WriteLine("[ETW] Engine will still consume process/image/thread events from the ring buffer.");

            // Tell the GUI whether we hold admin rights — an unelevated engine cannot read the
            // PEB of elevated processes, cannot kill them, and loses the ETW process-create feed.
            bool engineElevated = false;
            try
            {
                using var wid = WindowsIdentity.GetCurrent();
                engineElevated = new WindowsPrincipal(wid).IsInRole(WindowsBuiltInRole.Administrator);
            }
            catch { }
            EventBus.Status($"engine_elevated={(engineElevated ? 1 : 0)} etw={(etwSubscriber.IsRunning ? 1 : 0)}");
            EventBus.Status($"engine_log={(EngineLog.FilePath.Length > 0 ? EngineLog.FilePath : "none")} response={(Volatile.Read(ref EngineState.DetectOnlyMode) == 0 ? "terminate" : "detect")}");

            // Start the real-time event feed to the console UI and the command reader.
            EventBus.Status($"engine_started pid={Environment.ProcessId} usermode=1 shield={(skipShield ? 0 : 1)}");
            commandReader = new CommandReader();
            commandReader.OnCommand += cmd => EngineFeedRunner.HandleGuiCommand(cmd, storyteller!, virusTotalScanner, quarantineManager, realtimeScanner, tpmEngine, activeGuardian, storyFeed, usbGuard, memoryIntegrity, zeroDayEngine, mystralBridge, whitelistManager, fingerprintStore);
            commandReader.Start();

            // ── Mystral companion bridge: the sensor streams its findings here ──
            // Sensor data only — the engine corroborates high findings and remains the
            // only actor. The pipe never carries commands to Mystral except one fixed
            // read-only scan request, which the sensor answers with a memory pass.
            mystralBridge = new MystralBridgeServer(
                (pid, img, kind, sev, detail) =>
                {
                    Console.WriteLine($"[MYSTRAL] finding pid={pid} {img}: {kind} ({sev}) — {detail}");
                    EventBus.MystralFinding(pid, img, kind, sev, detail);
                    storyFeed!.AddDetection("mystral", sev, kind, $"{img} (pid {pid}): {detail}", pid);
                    storyteller!.ReportProcessStart(pid, 0, img);
                    if (sev == "high")
                    {
                        var (score, allow, audit, act) = storyteller.ReportMystralFinding(pid, img, kind);
                        Console.WriteLine($"[MYSTRAL] corroboration pid={pid} score={score} allow={allow} audit={audit} act={act}");
                        if (act)
                        {
                            var verdict = dcaEngine!.VerifyBeforeAct(pid);
                            EventBus.Alert(pid, img, score, verdict.Proceed ? "shield" : "veto",
                                (verdict.Proceed ? "Mystral second witness — engine engaging :: " : "Held by cross-verification :: ") + verdict.Reason);
                            if (verdict.Proceed && score >= SafeProcessKiller.KillScoreThreshold &&
                                SafeProcessKiller.Terminate(pid, $"Mystral memory finding {kind}", score))
                            {
                                EventBus.Detection("response", "shield", "Attacker terminated (Mystral witness)",
                                    $"pid {pid} killed at score {score} — Mystral {kind}", pid);
                            }
                        }
                        else if (audit)
                        {
                            EventBus.Alert(pid, img, score, "audit", $"Mystral {kind} under review — {detail}");
                        }
                    }
                },
                (pid, ppid, img, cmd, onDisk) =>
                {
                    EventBus.MystralProc(pid, ppid, img, cmd, onDisk);
                    storyteller!.ReportProcessStart(pid, ppid, img);
                },
                connected =>
                {
                    Console.WriteLine(connected ? "[MYSTRAL] sensor connected" : "[MYSTRAL] sensor disconnected");
                    EventBus.MystralStatus(connected);
                    if (connected && mystralBridge != null) mystralBridge.RequestScan();
                });
            mystralBridge.OnLog += m => Console.WriteLine("[MYSTRAL-BRIDGE] " + m);
            mystralBridge.Start();
            Console.WriteLine("[MYSTRAL] bridge server listening on pipe NexusMystralBridge");

            eventPumpThread = new Thread(() => EngineFeedRunner.EventPump(storyteller!, dcaEngine!, storyFeed!))
            { IsBackground = true, Name = "Nexus-EventPump" };
            eventPumpThread.Start();

            decayThread = new Thread(() =>
            {
                try
                {
                    while (Volatile.Read(ref EngineState.ShuttingDown) == 0)
                    {
                        Thread.Sleep(10000);
                        if (Volatile.Read(ref EngineState.ShuttingDown) != 0) break;
                        int n = storyteller!.DecayTick(60.0);
                        if (n > 0)
                            Console.WriteLine($"[DECAY] Applied half-life 60s decay to {n} process nodes");
                    }
                }
                catch (ThreadInterruptedException) { }
                catch (Exception ex)
                {
                    Console.WriteLine($"[DECAY] thread faulted (non-fatal): {ex.Message}");
                }
            })
            { IsBackground = true, Name = "Nexus-Decay" };
            decayThread.Start();

            confidenceWriterThread = new Thread(() =>
            {
                try
                {
                    while (Volatile.Read(ref EngineState.ShuttingDown) == 0)
                    {
                        Thread.Sleep(500);
                        if (Volatile.Read(ref EngineState.ShuttingDown) != 0 || basePointer == null) continue;
                        ref KernelBridge.RingBufferHeader hdr = ref Unsafe.AsRef<KernelBridge.RingBufferHeader>((void*)basePointer);
                        var top8 = storyteller!.Processes.Values
                            .OrderByDescending(n => n.Confidence)
                            .Take(8)
                            .Select(n => (Pid: n.Pid, Conf: (uint)Math.Clamp(n.Confidence, 0, 999)))
                            .ToList();
                        for (int i = 0; i < 8; i++) hdr.PidConfidence[i] = 0;
                        foreach (var (p, c) in top8)
                        {
                            int idx = (int)(p % 8);
                            uint cur = Volatile.Read(ref hdr.PidConfidence[idx]);
                            if (c > cur) Volatile.Write(ref hdr.PidConfidence[idx], c);
                        }
                    }
                }
                catch (ThreadInterruptedException) { }
                catch (Exception ex)
                {
                    Console.WriteLine($"[PIDCONF] thread faulted (non-fatal): {ex.Message}");
                }
            })
            { IsBackground = true, Name = "Nexus-PidConfidenceWriter" };
            confidenceWriterThread.Start();

            // Startup checkpoint: reaching this line proves the hardened process (including ACG,
            // which bans new executable pages) can actually run the engine. Release the pending
            // marker so the next start keeps ACG armed.
            ProcessMitigations.CheckpointHealthy();
            Console.WriteLine("[INFO] Init done. Press Ctrl+C to exit...");
            var cts = new CancellationTokenSource();
            Console.CancelKeyPress += (_, e) => { e.Cancel = true; cts.Cancel(); };

            // NOTE: bypass mode pauses enforcement (guardian/SAS/memory loops check it) but must
            // NOT terminate the main loop — killing it here turned the SubKit "Toggle bypass"
            // button into an engine shutdown and left the host with zero protection.
            int bypass = 0;
            long lastHiddenScan = 0;
            long lastStatsStamp = 0;
            while (!cts.IsCancellationRequested)
            {
                bypass = Volatile.Read(ref EngineState.BypassMode);
                try
                {
                if (basePointer != null)
                {
                    KernelBridge.ProcessRingBuffer(
                        (nint)basePointer, (nuint)RINGBUFFER_CAPACITY,
                        lbr =>
                        {
                            macroSmartHub.RouteHardwareEvent(lbr.ProcessId, lbr.SourceIp, lbr.TargetIp);
                        },
                        etw =>
                        {
                            var (score, allow, _, act) = storyteller!.ReportEtwTiRwx(etw.CallerPid, etw.AllocationBase);
                            Console.WriteLine($"[ETW][ring] caller={etw.CallerPid} target={etw.TargetPid} score={score}{(allow ? " [ALLOWLIST]" : "")}{(act ? " [SHIELD]" : "")}");
                            if (act && score >= SafeProcessKiller.KillScoreThreshold)
                            {
                                var verdict = dcaEngine!.VerifyBeforeAct(etw.CallerPid);
                                EventBus.Alert(etw.CallerPid, "RWX allocation", score, verdict.Proceed ? "shield" : "veto",
                                    $"RWX base=0x{etw.AllocationBase:X} :: {verdict.Reason}");
                                if (verdict.Proceed &&
                                    SafeProcessKiller.Terminate(etw.CallerPid, $"ETW-TI RWX allocation 0x{etw.AllocationBase:X}", score))
                                {
                                    EventBus.Detection("response", "shield", "Attacker terminated",
                                        $"pid {etw.CallerPid} killed at score {score} — RWX allocation 0x{etw.AllocationBase:X}", etw.CallerPid);
                                }
                            }
                        },
                        processConsumer: (ev, etype) =>
                        {
                            string name = ReadFixedAscii(ev.ImageName, 16);
                            string kind = etype == 1 ? "PROCESS_CREATE" : "PROCESS_EXIT";
                            macroSmartHub.RouteSoftwareEvent(ev.ProcessId, ev.ParentPid, kind, name);
                            if (etype == 1)
                            {
                                string imgName = string.IsNullOrEmpty(name) ? "unknown.exe" : name;
                                storyteller!.ReportProcessStart(ev.ProcessId, ev.ParentPid, imgName);
                                storyFeed!.AddProcessStart(ev.ProcessId, ev.ParentPid, imgName);
                                storyteller.VerifyAndAttachSignature(ev.ProcessId);
                                if (ev.ParentPid != 0 && ev.ParentPid != 4 && TryResolveRealPpid(ev.ProcessId, out uint actualPpid))
                                    storyteller.DetectPpidSpoofing(ev.ProcessId, ev.ParentPid, actualPpid);
                            }
                        },
                        imageConsumer: ev =>
                        {
                            string mod = ReadFixedAscii(ev.ModuleName, 32);
                            if (ev.ImageSize != 0)
                                factChecker!.AddValidModuleRange(ev.ImageBase, ev.ImageSize);
                            macroSmartHub.RouteSoftwareEvent(ev.ProcessId, 0, "IMAGE_LOAD", mod);
                        },
                        threadConsumer: ev =>
                        {
                            if (ev.IsRemote != 0)
                            {
                                var (score, allow, audit, act) = storyteller!.ReportThreadInjection(ev.ProcessId, ev.CreatingPid, ev.StartIp);
                                Console.WriteLine($"[INJECT] remote thread victim={ev.ProcessId} creator={ev.CreatingPid} tid={ev.ThreadId} score={score}{(allow ? " [ALLOWLIST]" : "")}{(audit ? " [AUDIT]" : "")}{(act ? " [SHIELD]" : "")}");
                                if (act)
                                {
                                    var verdict = dcaEngine!.VerifyBeforeAct(ev.CreatingPid);
                                    EventBus.Alert(ev.CreatingPid, "remote thread injection", score, verdict.Proceed ? "shield" : "veto",
                                        $"Remote thread -> victim={ev.ProcessId} start=0x{ev.StartIp:X} :: {verdict.Reason}");
                                    if (verdict.Proceed && score >= SafeProcessKiller.KillScoreThreshold &&
                                        SafeProcessKiller.Terminate(ev.CreatingPid, $"remote thread injection -> pid {ev.ProcessId} start=0x{ev.StartIp:X}", score))
                                    {
                                        EventBus.Detection("response", "shield", "Attacker terminated",
                                            $"pid {ev.CreatingPid} killed at score {score} — injected remote thread into pid {ev.ProcessId}", ev.CreatingPid);
                                    }
                                }
                                else if (audit)
                                    EventBus.Alert(ev.CreatingPid, "remote thread injection", score, "audit", $"Remote thread -> victim={ev.ProcessId}");
                            }
                            else
                            {
                                macroSmartHub.RouteSoftwareEvent(ev.ProcessId, ev.CreatingPid, "THREAD_CREATE", "thread");
                            }
                        },
                        networkConsumer: ev =>
                        {
                            Console.WriteLine($"[NET] pid={ev.ProcessId} {ev.RemoteIp:X8}:{ev.RemotePort} proto={ev.Protocol} blocked={ev.IsBlocked}");
                        },
                        preboot =>
                        {
                            Console.WriteLine($"[PRE-BOOT][RING] Summary event: Pass={preboot.ScanPass} TamperCount={preboot.TamperCount}/{preboot.FileCount} IDT=0x{preboot.IdtBase:X16} GDT=0x{preboot.GdtBase:X16}");
                            int penalty = storyteller!.ReportPrebootResult(preboot.TamperCount, preboot.FileCount, preboot.IdtBase, preboot.GdtBase, preboot.Cr0, preboot.Cr3);
                            if (penalty > 0) Console.WriteLine($"[PRE-BOOT][RING] Global DCA penalty: {penalty}");
                        },
                        ka =>
                        {
                            if (ka.EnginePid == 0 || ka.EnginePid == Environment.ProcessId)
                            {
                                uint response = ComputeHmacKaResponse(rootTrustKey, ka.Challenge);
                                // No driver to send response to - handle in user-mode
                                Console.WriteLine($"[KA-INVERTED] HMAC-SHA256 response computed (challenge=0x{ka.Challenge:X8}, response=0x{response:X8})");
                                kaMonitor?.TryRespondToChallenge(ka.Challenge, response, out _);
                            }
                        }
                    );
                }

                // ── Hidden process scan every 30 seconds ──────────────────
                if (bypass == 0 && Stopwatch.GetTimestamp() - lastHiddenScan > 30 * Stopwatch.Frequency)
                {
                    lastHiddenScan = Stopwatch.GetTimestamp();
                    int hidden = HiddenProcessScanner.Scan(storyteller!);
                    if (hidden > 0)
                        Console.WriteLine($"[HIDDEN-PROC] {hidden} discrepancy(ies) found this cycle");
                }
                
                // ── User-mode protection stats every 60 seconds ──────────────────
                // Edge-triggered stamp: the old modulo window was true for 15 s of every
                // minute and printed this ~66x/sec during that window, flooding the GUI feed.
                if (bypass == 0 && Stopwatch.GetTimestamp() - lastStatsStamp >= 60 * Stopwatch.Frequency)
                {
                    lastStatsStamp = Stopwatch.GetTimestamp();
                    var (procProtected, procViolations, procBlocked) = userModeProcessProtection?.GetStats() ?? (0, 0, 0);
                    var (regProtected, regViolations, regBlocked) = userModeRegistryProtection?.GetStats() ?? (0, 0, 0);
                    var (fsProtected, fsTracked, fsViolations, fsBlocked) = userModeFileSystemProtection?.GetStats() ?? (0, 0, 0, 0);
                    var (netTotal, netBlocked, netIPs) = userModeNetworkFilter?.GetStats() ?? (0, 0, 0);
                    var (selfTriggers, selfSuspicious, _) = userModeSelfDefense?.GetStats() ?? (0, 0, 0);
                    int sasTracked = sasEngine?.ScoredProcesses ?? 0;
                    int sasEnc = sasEngine?.EncryptingFlags ?? 0;
                    int memFindings = memoryIntegrity?.TotalFindings ?? 0;
                    int gScanned = activeGuardian?.TotalScanned ?? 0;
                    int gBlocked = activeGuardian?.TotalBlocked ?? 0;
                    int gUnread = activeGuardian?.UnreadableTotal ?? 0;
                    int sgScanned = scriptGuard?.TotalScanned ?? 0;
                    int sgHits = scriptGuard?.TotalHits ?? 0;
                    int sgBlocked = scriptGuard?.TotalBlocked ?? 0;
                    int sgDropped = scriptGuard?.DroppedBacklog ?? 0;
                    var zdayStats = zeroDayEngine?.GetStats() ?? (0, 0, 0, 0, 0);

                    Console.WriteLine($"[STATS] Process: {procProtected} protected, {procViolations} violations | Registry: {regProtected} protected, {regViolations} violations | Filesystem: {fsProtected} protected, {fsViolations} violations | Network: {netTotal} connections, {netBlocked} blocked, {netIPs} IPs, {WfpBlocker.ActiveBlockCount} WFP filters | SAS: {sasTracked} tracked, {sasEnc} encryption-flags | Memory: {memFindings} findings | Guardian: {gScanned} scanned, {gBlocked} blocked, {gUnread} unreadable | Script: {sgScanned} blocks, {sgHits} hits, {sgBlocked} blocked, {sgDropped} dropped | Zero-day file engine: {zdayStats.Analyses} analysed, {zdayStats.Flagged} flagged, {zdayStats.Halted} halted, {zdayStats.Dropped} dropped | Story: {storyFeed?.EpisodeCount ?? 0} episodes");
                    EventBus.Status($"guardian_stats scanned={gScanned} blocked={gBlocked} unreadable={gUnread}");
                    EventBus.Status($"script_stats scanned={sgScanned} hits={sgHits} blocked={sgBlocked} dropped={sgDropped} feed={(etwSubscriber?.AmsiContentSeen == true ? "live" : "silent")}");
                    EventBus.Status($"zeroday_stats analysed={zdayStats.Analyses} flagged={zdayStats.Flagged} halted={zdayStats.Halted} dropped={zdayStats.Dropped} cache={zdayStats.CacheHits} threshold={ZeroDayEngine.BlockScoreThreshold}");
                    EventBus.Status($"selfdefense_stats triggers={selfTriggers} suspicious={selfSuspicious}");

                    var kb = realtimeScanner != null
                        ? realtimeScanner.GetKnownBadStats()
                        : (FingerprintHits: 0, KnownBadBlocked: 0, DisputedHeld: 0);
                    EventBus.Status($"fingerprint_stats records={fingerprintStore?.Count ?? 0} exact={fingerprintStore?.ExactMatches ?? 0} same_code={fingerprintStore?.SameCodeMatches ?? 0} fuzzy={fingerprintStore?.FuzzyMatches ?? 0} hits={kb.FingerprintHits} knownbad_blocked={kb.KnownBadBlocked} disputed_held={kb.DisputedHeld} vt_knownbad_threshold={RealtimeScanner.KnownBadEngineThreshold}");
                }

                }
                catch (Exception loopEx)
                {
                    // A single faulted event or scan must never take down the engine.
                    Console.WriteLine($"[LOOP] consumer fault (non-fatal): {loopEx.Message}");
                }
                Thread.Sleep(15);
            }

            return EXIT_OK;
        }

        return EXIT_OK;
    }
    catch (Exception ex)
    {
        Console.Error.WriteLine($"[FATAL] Init failed: {ex}");
        return EXIT_INIT_FAIL;
    }
    finally
    {
        etwSubscriber?.Dispose();
        macroSmartHub?.Stop();
        kaMonitor?.Dispose();
        shield?.Dispose();
        tpmEngine?.Dispose();
        realtimeScanner?.Dispose();
        quarantineManager?.Dispose();
        virusTotalScanner?.Dispose();
        
        // Dispose new user-mode protection components
        userModeProcessProtection?.Dispose();
        userModeRegistryProtection?.Dispose();
        userModeFileSystemProtection?.Dispose();
        userModeNetworkFilter?.Dispose();
        userModeSelfDefense?.Dispose();
        injectionTracker?.Dispose();
        sasEngine?.Dispose();
        usbGuard?.Dispose();
        memoryIntegrity?.Dispose();
        persistenceGuard?.Dispose();
        scriptGuard?.Dispose();
        zeroDayEngine?.Dispose();
        activeGuardian?.Dispose();
        commandReader?.Dispose();
        bootkitScanner?.Dispose();
        mystralBridge?.Dispose();

        // Drop every WFP filter (dynamic session would also clean up on process exit,
        // this is the graceful path). The story sink goes away with the process.
        WfpBlocker.Close();
        EventBus.StoryFeed = null;
        
        if (ringView != null && basePointer != null)
        {
            ringView.SafeMemoryMappedViewHandle.ReleasePointer();
        }
        ringView?.Dispose();
        ringSection?.Dispose();
        factChecker?.Dispose();
        Volatile.Write(ref EngineState.ShuttingDown, 1);
        EngineLog.Shutdown();
    }

    static unsafe string ReadFixedAscii(byte* p, int max)
    {
        int n = 0;
        while (n < max && p[n] != 0) n++;
        return n == 0 ? string.Empty : System.Text.Encoding.ASCII.GetString(p, n);
    }

    static void OnLbrAnomaly(uint pid, ulong addr)
        => Console.WriteLine($"[LBR][pid={pid}] anomaly: jump to 0x{addr:X16} (outside legit module range)");

    static void InitRingBuffer(nint baseAddress, uint capacity)
    {
        if (baseAddress == 0) return;
        ref KernelBridge.RingBufferHeader hdr = ref Unsafe.AsRef<KernelBridge.RingBufferHeader>((void*)baseAddress);
        Volatile.Write(ref hdr.Head, 0);
        Volatile.Write(ref hdr.Tail, 0);
        Volatile.Write(ref hdr.Size, capacity);
        Volatile.Write(ref hdr.EventCount, 0);
    }
}

internal static class NativeMethods
{
    public const int ProcessBasicInformation = 0;

    [StructLayout(LayoutKind.Sequential)]
    public struct PROCESS_BASIC_INFORMATION
    {
        public IntPtr ExitStatus;
        public IntPtr PebBaseAddress;
        public IntPtr AffinityMask;
        public IntPtr BasePriority;
        public IntPtr UniqueProcessId;
        public IntPtr InheritedFromUniqueProcessId;
    }

    [DllImport("ntdll.dll")]
    public static extern int NtQueryInformationProcess(IntPtr ProcessHandle, int infoClass, out PROCESS_BASIC_INFORMATION pbi, int size, out int returnSize);
}