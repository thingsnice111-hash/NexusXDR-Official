using System;
using System.Collections.Generic;
using System.IO;
using System.Threading;
using System.Threading.Tasks;

namespace NexusAV.Engine;

/// <summary>
/// Bridges the engine's real detection state to the console UI:
///  - <see cref="EventPump"/> periodically publishes process snapshots, new graph edges,
///    threshold-crossing alerts and aggregate stats to <see cref="EventBus"/>.
///  - <see cref="HandleGuiCommand"/> executes on-demand actions requested by the UI
///    (scan, VT key/test, TPM attestation, quarantine list/restore/delete, self-defense).
/// Runs outside the unsafe top-level context so async APIs are usable.
/// </summary>
internal static class EngineFeedRunner
{
    private static int _mitigationSweepRunning;

    public static void EventPump(Storyteller st, DcaEngine dca, StorytellerStable feed)
    {
        var lastConf = new Dictionary<uint, int>();
        var alerted = new HashSet<uint>();
        var auditAlerted = new HashSet<uint>();
        int edgeCursor = 0;
        long lastPrune = 0;

        while (Volatile.Read(ref EngineState.ShuttingDown) == 0)
        {
            try
            {
                // Process nodes: emit only on confidence change.
                foreach (var node in st.Processes.Values)
                {
                    if (!lastConf.TryGetValue(node.Pid, out int prev) || prev != node.Confidence)
                    {
                        lastConf[node.Pid] = node.Confidence;
                        EventBus.Process(node.Pid, node.ParentPid, node.ImageName, node.Confidence,
                            node.InAllowlist, node.SigState.ToString());

                        var (audit, act) = Storyteller.Classify(node.Confidence, node.InAllowlist);
                        if (act)
                        {
                            if (!alerted.Contains(node.Pid))
                            {
                                alerted.Add(node.Pid);
                                var verdict = dca.VerifyBeforeAct(node.Pid);
                                EventBus.Alert(node.Pid, node.ImageName, node.Confidence,
                                    verdict.Proceed ? "shield" : "veto",
                                    (verdict.Proceed ? "Active attack chain — shield engaged :: " : "Held by cross-verification :: ") + verdict.Reason);
                            }
                        }
                        else if (!act && node.Confidence < 60)
                        {
                            alerted.Remove(node.Pid);
                            if (node.Confidence < 30)
                                auditAlerted.Remove(node.Pid);
                        }
                        else if (audit)
                        {
                            // Advisory alerts are reported once per escalation, not on every
                            // confidence change — decay ticks used to re-alert continuously
                            // and flood the GUI feed.
                            if (auditAlerted.Add(node.Pid))
                                EventBus.Alert(node.Pid, node.ImageName, node.Confidence, "audit",
                                    "Correlated signals under review");
                        }
                    }
                }

                // New cross-process graph edges since last cycle.
                foreach (var e in st.Graph.SnapshotSince(ref edgeCursor))
                {
                    EventBus.Edge(e.SrcPid, e.DstPid, e.Type.ToString(), e.Weight, e.Timestamp, e.Extra);
                    feed.AddEdge(e.SrcPid, e.DstPid, e.Type.ToString(), e.Weight, e.Extra);
                }

                // Drop graph state whose endpoints are both gone (aliveness from the
                // shared snapshot cache — this pump never takes its own snapshot).
                long nowMs = Environment.TickCount64;
                if (nowMs - lastPrune >= 6000)
                {
                    lastPrune = nowMs;
                    var snap = ProcessSnapshotCache.Snapshot;
                    var alive = new HashSet<uint>(snap.Count + 4);
                    for (int i = 0; i < snap.Count; i++) alive.Add(snap[i].Pid);
                    st.Graph.Prune(pid => alive.Contains(pid));
                }
            }
            catch
            {
                // Feed must never crash the detection engine.
            }

            Thread.Sleep(800);
        }
    }

    public static void HandleGuiCommand(
        CommandReader.Command cmd,
        Storyteller st,
        VirusTotalScanner? vt,
        QuarantineManager? qm,
        RealtimeScanner? rs,
        TpmValidationEngine? tpm,
        ActiveGuardian? guardian,
        StorytellerStable? storyFeed,
        UsbDeviceGuard? usbGuard,
        UserModeMemoryIntegrityMonitor? memIntegrity,
        ZeroDayEngine? zeroDay,
        MystralBridgeServer? mystral,
        WhitelistManager? whitelist,
        FingerprintStore? fingerprints)
    {
        try
        {
            switch (cmd.Name)
            {
                case "scan":
                {
                    string path = Get(cmd, "p");
                    if (string.IsNullOrEmpty(path)) return;
                    EventBus.Status($"scan_started path={path}");
                    _ = Task.Run(async () =>
                    {
                        try
                        {
                            if (vt == null) return;
                            var result = await vt.ScanAnyFileAsync(path);
                            EventBus.Scan(path, result.MaliciousCount, result.TotalEngines,
                                result.DetectionNames, result.IsMalicious, result.ErrorMessage);
                            if (result.IsMalicious && qm != null)
                            {
                                bool ok = qm.QuarantineFile(path, $"VT: {result.DetectionNames}", out var entry);
                                if (ok && entry != null)
                                    EventBus.Quarantine(entry.QuarantinePath, entry.OriginalPath,
                                        "quarantined", $"VT {result.MaliciousCount}/{result.TotalEngines}", entry.SHA256);
                            }
                        }
                        catch (Exception ex)
                        {
                            EventBus.Scan(path, 0, 0, "", false, ex.Message);
                        }
                    });
                    break;
                }

                case "vt_setkey":
                {
                    string key = Get(cmd, "k");
                    vt?.SetApiKey(key);
                    EventBus.VtStatus(!string.IsNullOrEmpty(key), key.Length > 0 ? "API key configured" : "API key cleared");
                    break;
                }

                case "vt_test":
                {
                    _ = Task.Run(async () =>
                    {
                        if (vt == null) { EventBus.VtStatus(false, "Scanner unavailable"); return; }
                        var (ok, status) = await vt.TestConnectivity();
                        EventBus.VtStatus(ok, status);
                    });
                    break;
                }

                case "tpm":
                {
                    if (tpm == null) return;
                    _ = Task.Run(() =>
                    {
                        var r = tpm.RunAttestation();
                        st.ReportFirmwareAttestation(r);
                        string sb = r.SecureBootQueried ? (r.SecureBootEnabled ? "ON" : "OFF") : "n/a";
                        string uefi = r.UefiBootOrderPresent ? (r.BootPathTamper ? "TAMPER" : "OK") : "n/a";
                        EventBus.Tpm(r.Summary, sb, uefi, r.BootPathTamper, r.TpmPresent, r.TcgLogParsed, r.Findings);
                    });
                    break;
                }

                case "quarantine_list":
                {
                    if (qm == null) return;
                    foreach (var e in qm.GetQuarantineEntries())
                        EventBus.Quarantine(e.QuarantinePath, e.OriginalPath, "list", e.ThreatName, e.SHA256);
                    break;
                }

                case "quarantine_restore":
                {
                    if (qm == null) return;
                    string qpath = Get(cmd, "p");
                    bool ok = qm.RestoreFile(qpath, out var restored);
                    EventBus.Status(ok ? $"quarantine_restored path={restored}" : $"quarantine_restore_failed path={qpath}");
                    if (ok) EventBus.Quarantine(qpath, restored ?? "", "restored", "", "");
                    break;
                }

                case "quarantine_delete":
                {
                    if (qm == null) return;
                    string qpath = Get(cmd, "p");
                    bool ok = qm.DeleteQuarantinedFile(qpath);
                    EventBus.Status(ok ? $"quarantine_deleted path={qpath}" : $"quarantine_delete_failed path={qpath}");
                    if (ok) EventBus.Quarantine(qpath, "", "deleted", "", "");
                    break;
                }

                case "selfdefense":
                {
                    int cur = Volatile.Read(ref EngineState.BypassMode);
                    int next = cur == 0 ? 1 : 0;
                    Volatile.Write(ref EngineState.BypassMode, next);
                    EventBus.Status(next == 1 ? "selfdefense_bypass_on" : "selfdefense_bypass_off");
                    break;
                }

                case "response":
                {
                    // Response mode: "detect" (default, report only, never kill) or
                    // "terminate" (kills confirmed attackers). Empty p toggles.
                    string want = Get(cmd, "p");
                    int next = want switch
                    {
                        "terminate" => 0,
                        "detect" => 1,
                        _ => Volatile.Read(ref EngineState.DetectOnlyMode) == 0 ? 1 : 0
                    };
                    Volatile.Write(ref EngineState.DetectOnlyMode, next);
                    SafeProcessKiller.OperatorSetResponseMode(next);
                    EventBus.Status(next == 0 ? "response_terminate_on" : "response_detect_only_on");
                    break;
                }

                case "resume":
                {
                    // Thaw one halted pid (p=pid) or every halted pid (p=all).
                    string who = Get(cmd, "p");
                    if (who == "all")
                    {
                        int n = SafeProcessKiller.ThawAll();
                        EventBus.Status($"resume_all count={n}");
                        Console.WriteLine($"[RESPONSE] operator thawed {n} halted process(es)");
                    }
                    else if (uint.TryParse(who, out uint rpid))
                    {
                        string outcome = SafeProcessKiller.Resume(rpid);
                        EventBus.Status($"resume_one pid={rpid} outcome={outcome.Replace(' ', '_')}");
                        Console.WriteLine($"[RESPONSE] resume pid={rpid}: {outcome}");
                    }
                    break;
                }

                case "halt":
                {
                    // Operator-initiated reversible containment: freeze the tree, delete nothing.
                    // The safer half of the kill button, and the action the zero-day engine takes
                    // on its own for a file that scored hostile from structure alone.
                    if (!uint.TryParse(Get(cmd, "p"), out uint hpid) || hpid == 0)
                    { EventBus.Status("halt_bad_pid"); break; }
                    int n = SafeProcessKiller.HaltOnly(hpid, "analyst halt from the console");
                    EventBus.Status($"halt_one pid={hpid} halted={n}");
                    break;
                }

                case "zday":
                {
                    // Operator-triggered local analysis of one file (the console "Inspect" button).
                    // Answers with the real verdict, including "not analysed" — never a fake clean.
                    if (zeroDay == null) { EventBus.Status("zeroday_unavailable"); break; }
                    string zpath = Get(cmd, "p");
                    if (string.IsNullOrEmpty(zpath)) { EventBus.Status("zeroday_bad_path"); break; }
                    _ = Task.Run(() =>
                    {
                        var v = zeroDay.Analyze(zpath, useCache: false);
                        if (v == null)
                        {
                            EventBus.Status($"zeroday_skipped path={zpath.Replace(' ', '_')} reason=extension_or_size");
                            EventBus.Detection("malware", "audit", "File not analysed",
                                $"{zpath} is outside the scope of the structure engine (only code files and document lures between 64 B and 80 MB are read). This is NOT a clean verdict.", 0);
                            return;
                        }
                        EventBus.Status($"zeroday_verdict path={zpath.Replace(' ', '_')} score={v.Score}");
                        EventBus.Detection("malware", v.IsBlocker ? "high" : v.IsWatchable ? "medium" : "audit",
                            v.IsWatchable ? "Unknown file judged hostile" : "Unknown file judged locally",
                            v.Summary, 0);
                    });
                    break;
                }

                case "usb":
                {
                    // Per-device USB storage control (CfgMgr32). p = list | block | unblock, id = instance.
                    if (usbGuard == null) { EventBus.Status("usb_unavailable"); break; }
                    string op = Get(cmd, "p");
                    switch (op)
                    {
                        case "block":
                        case "unblock":
                        {
                            string id = Get(cmd, "id");
                            var r = op == "block" ? usbGuard.Block(id) : usbGuard.Unblock(id);
                            if (!r.Ok)
                                EventBus.Detection("usb", "medium", $"USB {op} failed", $"{id}: {r.Message}", 0);
                            break;
                        }
                        default: // "list" / "status" / anything else — reflect the real device state
                            usbGuard.PublishStatus();
                            break;
                    }
                    break;
                }

                case "memscan":
                {
                    if (memIntegrity == null) { EventBus.Status("memscan_unavailable"); break; }
                    EventBus.Status("memscan_started");
                    _ = Task.Run(() =>
                    {
                        int findings = memIntegrity.ScanNow();
                        EventBus.Status($"memscan_done findings={findings} scans={memIntegrity.TotalScans}");
                    });
                    break;
                }

                case "story_get":
                {
                    if (storyFeed == null) { EventBus.Status("story_unavailable"); break; }
                    storyFeed.PublishSnapshot();
                    break;
                }

                case "kill":
                {
                    // Analyst-initiated termination from the console (mitigation button).
                    if (!uint.TryParse(Get(cmd, "p"), out uint kpid) || kpid == 0)
                    { EventBus.Status($"kill_bad_pid p={Get(cmd, "p")}"); break; }
                    string kimg = st.Processes.TryGetValue(kpid, out var kn) ? kn.ImageName : $"pid{kpid}";
                    string? refuse = RefuseKill(kpid, kimg);
                    if (refuse != null)
                    {
                        EventBus.Status($"kill_refused pid={kpid} reason={refuse}");
                        EventBus.Detection("response", "audit", "Mitigation refused", $"{kimg} (pid {kpid}): {refuse}", kpid);
                        break;
                    }
                    try
                    {
                        using var kp = System.Diagnostics.Process.GetProcessById((int)kpid);
                        kp.Kill();
                        EventBus.Status($"kill_ok pid={kpid} img={kimg}");
                        storyFeed?.AddMitigation("terminated", kpid, kimg, "process terminated by analyst from the console");
                        EventBus.Detection("response", "shield", "Analyst mitigation: process terminated",
                            $"{kimg} (pid {kpid}) terminated from the console", kpid);
                    }
                    catch (Exception kex)
                    {
                        EventBus.Status($"kill_failed pid={kpid} err={kex.Message}");
                        storyFeed?.AddMitigation("kill failed", kpid, kimg, kex.Message);
                    }
                    break;
                }

                case "netblock":
                case "netunblock":
                {
                    // Outbound containment for one image via the WFP dynamic session; the
                    // filter dies with the engine, so containment is never persistent.
                    if (!uint.TryParse(Get(cmd, "p"), out uint npid) || npid == 0)
                    { EventBus.Status($"{cmd.Name}_bad_pid"); break; }
                    if (!st.Processes.TryGetValue(npid, out var nn) || string.IsNullOrEmpty(nn.FullImagePath))
                    {
                        EventBus.Status($"{cmd.Name}_no_image pid={npid}");
                        break;
                    }
                    bool block = cmd.Name == "netblock";
                    string? werr = block ? WfpBlocker.BlockImage(nn.FullImagePath) : WfpBlocker.UnblockImage(nn.FullImagePath);
                    if (werr != null)
                    {
                        EventBus.Status($"{cmd.Name}_failed img={nn.ImageName} err={werr}");
                        storyFeed?.AddMitigation(block ? "network containment failed" : "network release failed", npid, nn.ImageName, werr);
                        break;
                    }
                    EventBus.Status($"{cmd.Name}_ok pid={npid} img={nn.ImageName}");
                    storyFeed?.AddMitigation(block ? "outbound network contained" : "outbound network released", npid, nn.ImageName,
                        $"{(block ? "outbound connects blocked" : "outbound connects restored")} for {nn.FullImagePath} (WFP dynamic session)");
                    EventBus.Detection("network", block ? "shield" : "audit",
                        block ? "Analyst mitigation: network containment applied" : "Network containment lifted",
                        $"{nn.ImageName} (pid {npid}) — {(block ? "outbound connects blocked" : "outbound connects restored")} via WFP", npid);
                    break;
                }

                case "guard_allow":
                {
                    if (guardian == null) return;
                    string scope = Get(cmd, "scope");
                    switch (scope)
                    {
                        case "once":
                            if (uint.TryParse(Get(cmd, "p"), out uint apid)) guardian.AllowOnce(apid);
                            EventBus.Status($"guard_allow_once pid={Get(cmd, "p")}");
                            break;
                        case "rule":
                            guardian.AllowRule(Get(cmd, "rule"));
                            EventBus.Status($"guard_allow_rule rule={Get(cmd, "rule")}");
                            break;
                        case "image":
                            guardian.AllowImage(Get(cmd, "img"));
                            EventBus.Status($"guard_allow_image img={Get(cmd, "img")}");
                            break;
                    }
                    break;
                }

                case "guard_quarantine":
                {
                    string path = Get(cmd, "p");
                    if (string.IsNullOrEmpty(path) || qm == null) return;
                    bool ok = qm.QuarantineFile(path, "ActiveGuardian: command-line rule", out var qe);
                    if (ok && qe != null)
                        EventBus.Quarantine(qe.QuarantinePath, qe.OriginalPath, "quarantined", "ActiveGuardian", qe.SHA256);
                    else
                        EventBus.Detection("guard", "medium", "Quarantine failed", path, 0);
                    break;
                }

                case "mystral_scan":
                {
                    // Forward the console's "scan now" to the attached sensor. The pipe carries
                    // exactly one fixed read-only request; Mystral ignores anything else.
                    if (mystral == null) { EventBus.Status("mystral_bridge_unavailable"); break; }
                    bool sent = mystral.RequestScan();
                    EventBus.Status(sent ? "mystral_scan_requested" : "mystral_scan_unreachable");
                    break;
                }

                case "mitigations_self":
                {
                    var info = ProcessMitigations.QuerySelf();
                    EventBus.MitigationRow(info.Pid, info.Image, info.DecodedSummary(), info.Error);
                    EventBus.HardenStatus(ProcessMitigations.LastAcgRequested, ProcessMitigations.LastAcgActive,
                        ProcessMitigations.LastAcgSource, ProcessMitigations.LastDetail);
                    EventBus.MitigationDone(1, "self");
                    break;
                }

                case "mitigations_pid":
                {
                    if (!uint.TryParse(Get(cmd, "p"), out uint mtpid))
                    { EventBus.Status("mitigations_bad_pid"); break; }
                    var info = ProcessMitigations.QueryProcess(mtpid);
                    EventBus.MitigationRow(info.Pid, info.Image, info.DecodedSummary(), info.Error);
                    EventBus.MitigationDone(1, "pid=" + mtpid);
                    break;
                }

                case "mitigations_sweep":
                {
                    // Read-only, single-pass, hard-capped: GetProcessMitigationPolicy needs only
                    // PROCESS_QUERY_LIMITED_INFORMATION, so nothing is injected and nothing is written.
                    if (!int.TryParse(Get(cmd, "p"), out int mtmax) || mtmax <= 0) mtmax = 64;
                    if (Interlocked.CompareExchange(ref _mitigationSweepRunning, 1, 0) != 0)
                    { EventBus.Status("mitigation_sweep_already_running"); break; }
                    EventBus.Status($"mitigation_sweep_started cap={mtmax}");
                    _ = Task.Run(() =>
                    {
                        try
                        {
                            var sweep = ProcessMitigations.SnapshotAll(mtmax);
                            foreach (var r in sweep.Rows)
                                EventBus.MitigationRow(r.Pid, r.Image, r.DecodedSummary(), r.Error);
                            EventBus.MitigationDone(sweep.Rows.Count,
                                $"read={sweep.Rows.Count - sweep.Denied} denied={sweep.Denied} examined={sweep.Examined}");
                        }
                        catch (Exception ex)
                        {
                            EventBus.MitigationDone(0, "sweep_fault:" + ex.GetType().Name);
                        }
                        finally { Interlocked.Exchange(ref _mitigationSweepRunning, 0); }
                    });
                    break;
                }

                case "mystral_kill":
                {
                    // Analyst mitigation from the Mystral tab — same rails as the regular kill
                    // button: protected pids/images refused, engine is the only actor.
                    if (!uint.TryParse(Get(cmd, "p"), out uint mkpid) || mkpid == 0)
                    { EventBus.Status("mystral_kill_bad_pid"); break; }
                    string mkimg = st.Processes.TryGetValue(mkpid, out var mkn) ? mkn.ImageName : $"pid{mkpid}";
                    string? mrefuse = RefuseKill(mkpid, mkimg);
                    if (mrefuse != null)
                    {
                        EventBus.Status($"mystral_kill_refused pid={mkpid} reason={mrefuse}");
                        EventBus.Detection("response", "audit", "Mystral mitigation refused", $"{mkimg} (pid {mkpid}): {mrefuse}", mkpid);
                        break;
                    }
                    try
                    {
                        using var mkp = System.Diagnostics.Process.GetProcessById((int)mkpid);
                        mkp.Kill();
                        EventBus.Status($"mystral_kill_ok pid={mkpid} img={mkimg}");
                        storyFeed?.AddMitigation("terminated", mkpid, mkimg, "process terminated by analyst from the Mystral tab");
                        EventBus.Detection("response", "shield", "Analyst mitigation (Mystral tab): process terminated",
                            $"{mkimg} (pid {mkpid}) terminated from the console", mkpid);
                    }
                    catch (Exception mkex)
                    {
                        EventBus.Status($"mystral_kill_failed pid={mkpid} err={mkex.Message}");
                        storyFeed?.AddMitigation("kill failed", mkpid, mkimg, mkex.Message);
                    }
                    break;
                }

                case "mystral_vt":
                {
                    // Cloud verdict for the image behind a Mystral finding (hash-only, no upload).
                    if (vt == null) { EventBus.Status("mystral_vt_unavailable"); break; }
                    if (!uint.TryParse(Get(cmd, "p"), out uint vtpid) || vtpid == 0)
                    { EventBus.Status("mystral_vt_bad_pid"); break; }
                    string vtpath = MystralImagePath(vtpid);
                    if (string.IsNullOrEmpty(vtpath)) { EventBus.Status($"mystral_vt_no_image pid={vtpid}"); break; }
                    EventBus.Status($"mystral_vt_started pid={vtpid} path={vtpath.Replace(' ', '_')}");
                    _ = Task.Run(async () =>
                    {
                        try
                        {
                            var result = await vt.ScanAnyFileAsync(vtpath);
                            EventBus.Scan(vtpath, result.MaliciousCount, result.TotalEngines, result.DetectionNames, result.IsMalicious, result.ErrorMessage);
                            if (result.IsMalicious && qm != null)
                            {
                                bool ok = qm.QuarantineFile(vtpath, $"VT: {result.DetectionNames}", out var entry);
                                if (ok && entry != null)
                                    EventBus.Quarantine(entry.QuarantinePath, entry.OriginalPath, "quarantined", $"VT {result.MaliciousCount}/{result.TotalEngines}", entry.SHA256);
                            }
                        }
                        catch (Exception ex)
                        {
                            EventBus.Scan(vtpath, 0, 0, "", false, ex.Message);
                        }
                    });
                    break;
                }

                case "mystral_quar":
                {
                    // Quarantine the on-disk image behind a Mystral finding.
                    if (qm == null) { EventBus.Status("mystral_quar_unavailable"); break; }
                    if (!uint.TryParse(Get(cmd, "p"), out uint qpid) || qpid == 0)
                    { EventBus.Status("mystral_quar_bad_pid"); break; }
                    string qpath = MystralImagePath(qpid);
                    if (string.IsNullOrEmpty(qpath)) { EventBus.Status($"mystral_quar_no_image pid={qpid}"); break; }
                    bool qok = qm.QuarantineFile(qpath, "Mystral tab: analyst quarantine", out var qe);
                    if (qok && qe != null)
                        EventBus.Quarantine(qe.QuarantinePath, qe.OriginalPath, "quarantined", "Mystral tab", qe.SHA256);
                    else
                        EventBus.Detection("response", "medium", "Quarantine failed (Mystral tab)", qpath, qpid);
                    break;
                }

                case "whitelist_add":
                {
                    if (whitelist == null) { EventBus.Status("whitelist_unavailable"); break; }
                    string wpath = Get(cmd, "p");
                    if (string.IsNullOrEmpty(wpath)) { EventBus.Status("whitelist_bad_path"); break; }
                    string note = Get(cmd, "note");
                    whitelist.Add(wpath, "gui", note);
                    EventBus.WhitelistEntry(wpath, "added", note);
                    EventBus.Status($"whitelist_added path={wpath.Replace(' ', '_')}");
                    break;
                }

                case "whitelist_remove":
                {
                    if (whitelist == null) { EventBus.Status("whitelist_unavailable"); break; }
                    string wpath = Get(cmd, "p");
                    if (string.IsNullOrEmpty(wpath)) { EventBus.Status("whitelist_bad_path"); break; }
                    whitelist.Remove(wpath);
                    EventBus.WhitelistEntry(wpath, "removed", "");
                    EventBus.Status($"whitelist_removed path={wpath.Replace(' ', '_')}");
                    break;
                }

                case "whitelist_list":
                {
                    if (whitelist == null) { EventBus.Status("whitelist_unavailable"); break; }
                    EventBus.WhitelistEntry("", "list_begin", "");
                    foreach (var entry in whitelist.GetAll())
                        EventBus.WhitelistEntry(entry.Path, "list", entry.Note);
                    EventBus.WhitelistDone(whitelist.Count);
                    break;
                }

                case "fp_add":
                {
                    if (fingerprints == null) { EventBus.Status("fingerprint_unavailable"); break; }
                    string fpath = Get(cmd, "p");
                    if (string.IsNullOrEmpty(fpath) || !File.Exists(fpath)) { EventBus.Status("fingerprint_bad_path"); break; }
                    string note = Get(cmd, "note");
                    var fp = FileFingerprinter.Compute(fpath, "manual", note);
                    if (fp == null) { EventBus.Status($"fingerprint_failed path={fpath}"); break; }
                    bool added = fingerprints.Add(fp);
                    EventBus.FpEntry(added ? "added" : "duplicate", fp.Sha256, fp.ImportHash, fp.Source, fp.Note, fp.Path);
                    EventBus.Detection("malware", "high", "File recorded as known-bad",
                        $"{Path.GetFileName(fpath)} was added to the local known-bad fingerprint store. Any file with this hash is quarantined and any process running it is frozen the moment it is seen. Remove the record here if this was a mistake.",
                        0);
                    EventBus.Status($"fingerprint_added sha={Short(fp.Sha256)} new={(added ? 1 : 0)} total={fingerprints.Count}");
                    EventBus.FpDone(fingerprints.Count);
                    break;
                }

                case "fp_remove":
                {
                    if (fingerprints == null) { EventBus.Status("fingerprint_unavailable"); break; }
                    string sha = Get(cmd, "sha");
                    if (string.IsNullOrEmpty(sha)) { EventBus.Status("fingerprint_bad_sha"); break; }
                    bool removed = fingerprints.Remove(sha);
                    EventBus.FpEntry(removed ? "removed" : "not_found", sha, "", "", "", "");
                    EventBus.Status($"fingerprint_removed sha={Short(sha)} found={(removed ? 1 : 0)} total={fingerprints.Count}");
                    EventBus.FpDone(fingerprints.Count);
                    break;
                }

                case "fp_list":
                {
                    if (fingerprints == null) { EventBus.Status("fingerprint_unavailable"); break; }
                    EventBus.FpEntry("list_begin", "", "", "", "", "");
                    foreach (var e in fingerprints.GetAll())
                        EventBus.FpEntry("list", e.Sha256, e.ImportHash, e.Source, e.Note, e.Path);
                    EventBus.FpDone(fingerprints.Count);
                    break;
                }

                case "fp_scan":
                {
                    // Analyst inspection only: computes the identity of one file and reports it.
                    // Nothing is recorded, so this can never block a file by accident.
                    string fpath = Get(cmd, "p");
                    if (string.IsNullOrEmpty(fpath) || !File.Exists(fpath)) { EventBus.Status("fingerprint_bad_path"); break; }
                    var fp = FileFingerprinter.Compute(fpath, "scan", "");
                    if (fp == null) { EventBus.Status($"fingerprint_failed path={fpath}"); break; }
                    string match = "";
                    if (fingerprints != null)
                    {
                        var hit = fingerprints.Lookup(fp.Sha256, fp.ImportHash, fp.SectionHashes, fp.Fuzzy);
                        if (hit is { } m) match = m.Kind;
                    }
                    EventBus.FpEntry("scan", fp.Sha256, fp.ImportHash, fp.Source,
                        match.Length > 0 ? $"matches a known-bad record ({match})" : "no known-bad record matches", fp.Path);
                    EventBus.Status($"fingerprint_scan sha={Short(fp.Sha256)} imp={Short(fp.ImportHash)} match={(match.Length > 0 ? match : "none")} size={fp.Size}");
                    break;
                }

                default:
                    break;
            }
        }
        catch (Exception ex)
        {
            EventBus.Status($"command_error {cmd.Name}: {ex.Message}");
        }
    }

    private static string Short(string s) => s.Length <= 16 ? s : s[..16];

    private static string Get(CommandReader.Command c, string key) =>
        c.Fields.TryGetValue(key, out var v) ? v : string.Empty;

    /// <summary>Resolves the on-disk image path for a Mystral-reported pid (same-user peers only).</summary>
    private static string MystralImagePath(uint pid)
    {
        string path = SafeProcessKiller.ImagePathOf(pid);
        if (!string.IsNullOrEmpty(path)) return path;
        try
        {
            using var p = System.Diagnostics.Process.GetProcessById((int)pid);
            return p.MainModule?.FileName ?? "";
        }
        catch
        {
            return "";
        }
    }

    /// <summary>
    /// Safety gate for analyst-initiated termination: never our own process, never the
    /// kernel/idle pids, never Windows-critical images whose death reboots the box.
    /// </summary>
    private static string? RefuseKill(uint pid, string image)
    {
        if (pid <= 8) return "protected system pid";
        if (pid == (uint)Environment.ProcessId) return "refusing to terminate the engine itself";
        switch (image.ToLowerInvariant())
        {
            case "smss.exe":
            case "csrss.exe":
            case "wininit.exe":
            case "winlogon.exe":
            case "services.exe":
            case "lsass.exe":
                return "Windows-critical process";
        }
        return null;
    }
}
