using System;
using System.Threading;
using Microsoft.Diagnostics.Tracing;
using Microsoft.Diagnostics.Tracing.Session;

namespace NexusAV.Engine;

/// <summary>
/// User-mode ETW listener. Two feeds:
///  1. Cross-process memory APIs used in injection chains — defensive telemetry only:
///     VirtualAlloc(RWX), WriteProcessMemory, SetThreadContext, MapViewOfSection.
///  2. Script CONTENT via the AMSI provider. Every script block PowerShell (and other AMSI
///     clients) execute is submitted to AMSI, and Windows mirrors those scans onto
///     Microsoft-Antimalware-Scan-Interface. Consuming it gives us the text of the attack
///     without registering an AMSI provider, without a logging policy change and without
///     injecting a DLL into anyone.
/// </summary>
public sealed class EtwSubscriber : IDisposable
{
    public const uint PageExecuteReadWrite = 0x40;
    public const uint PageExecuteWriteCopy = 0x80;

    private const int MinScriptChars = 8;
    private const int MaxScriptChars = 65_536;

    private readonly Action<KernelBridge.EtwTiTelemetryEvent> _onEvent;
    private readonly Action<uint, uint, string>? _onProcessStart;
    private readonly Action<uint, string, string>? _onScriptContent;
    private TraceEventSession? _session;
    private Thread? _thread;
    private volatile bool _running;
    private int _amsiSchemaLogged;
    private int _amsiEmptyLogged;

    public bool IsRunning => _running;
    public string? LastError { get; private set; }
    /// <summary>True once the AMSI provider has delivered at least one text payload.</summary>
    public bool AmsiContentSeen { get; private set; }

    public EtwSubscriber(Action<KernelBridge.EtwTiTelemetryEvent> onEvent,
        Action<uint, uint, string>? onProcessStart = null,
        Action<uint, string, string>? onScriptContent = null)
    {
        _onEvent = onEvent;
        _onProcessStart = onProcessStart;
        _onScriptContent = onScriptContent;
    }

    public bool Start()
    {
        if (_running) return true;
        try
        {
            string name = "NexusAV-ETW-" + Environment.ProcessId;
            try { TraceEventSession.GetActiveSession(name)?.Stop(); } catch { }

            _session = new TraceEventSession(name);
            _session.StopOnDispose = true;

            TryEnable(_session, "Microsoft-Windows-Threat-Intelligence");
            TryEnable(_session, "Microsoft-Windows-Kernel-Audit-API-Calls");
            TryEnable(_session, "Microsoft-Windows-Kernel-Process");

            // Script content feed. These are read-only ETW consumers: the engine creates its
            // own session and subscribes to providers Windows already emits. No registry
            // policy is touched, no AMSI provider is registered, nothing is injected.
            if (_onScriptContent != null)
            {
                TryEnable(_session, "Microsoft-Antimalware-Scan-Interface");
                TryEnable(_session, "Microsoft-Windows-PowerShell");
            }

            _session.Source.Dynamic.All += OnDynamicEvent;
            _running = true;
            _thread = new Thread(ProcessLoop)
            {
                IsBackground = true,
                Name = "NexusAV-ETW"
            };
            _thread.Start();
            Console.WriteLine($"[ETW] Subscriber started (TI + Kernel-Audit-API-Calls + Kernel-Process{(_onScriptContent != null ? " + AMSI + PowerShell" : "")}).");
            return true;
        }
        catch (Exception ex)
        {
            LastError = ex.Message;
            Console.WriteLine($"[ETW] Failed to start session (admin / no PPL TI is expected on some hosts): {ex.Message}");
            DisposeSession();
            _running = false;
            return false;
        }
    }

    private static void TryEnable(TraceEventSession session, string provider)
    {
        try
        {
            session.EnableProvider(provider, TraceEventLevel.Informational);
            if (provider.Contains("Threat-Intelligence"))
                Console.WriteLine("[ETW] Threat-Intelligence provider ENABLED — full kernel telemetry feed active");
        }
        catch (Exception ex)
        {
            if (provider.Contains("Threat-Intelligence"))
                Console.WriteLine($"[ETW] Provider {provider} not enabled: {ex.Message} — host restricts TI to PPL-signed agents or SeDebugPrivilege; injection telemetry falls back to Kernel-Audit-API-Calls (coarser)");
            else
                Console.WriteLine($"[ETW] Provider {provider} not enabled: {ex.Message}");
        }
    }

    private void ProcessLoop()
    {
        try
        {
            _session?.Source.Process();
        }
        catch (Exception ex)
        {
            if (_running)
                Console.WriteLine($"[ETW] Process loop ended: {ex.Message}");
        }
    }

    private void OnDynamicEvent(TraceEvent data)
    {
        try
        {
            string ev = data.EventName ?? string.Empty;
            string provider = data.ProviderName ?? string.Empty;

            // Near-real-time process-create feed for the Active Guardian.
            if (_onProcessStart != null && Contains(provider, "Kernel-Process") &&
                (Contains(ev, "ProcessStart") || Contains(ev, "Win32Start")))
            {
                uint newPid = unchecked((uint)data.ProcessID);
                uint parent = ReadUInt(data, "ParentId", "ParentProcessId", "PPID");
                string img = ReadStr(data, "ImageFileName", "ImageName", "ProcessName");
                if (newPid != 0)
                {
                    _onProcessStart.Invoke(newPid, parent, img);
                    return;
                }
            }

            uint caller = unchecked((uint)data.ProcessID);

            // Script-content feed. AMSI Scan events carry the exact text that was handed to
            // AMSI before execution; PowerShell 4104/800 carry the same blocks natively.
            // Returning here keeps script events out of the injection telemetry path below.
            if (_onScriptContent != null &&
                (Contains(provider, "Antimalware-Scan-Interface") || Contains(provider, "PowerShell")))
            {
                bool amsi = Contains(provider, "Antimalware-Scan-Interface");
                if (amsi)
                {
                    if (Interlocked.Exchange(ref _amsiSchemaLogged, 1) == 0)
                        Console.WriteLine($"[ETW][AMSI] first event: name={ev} fields=[{FieldNames(data)}]");
                    string content = ExtractScriptContent(data);
                    if (content.Length < MinScriptChars)
                    {
                        if (Interlocked.Exchange(ref _amsiEmptyLogged, 1) == 0)
                            Console.WriteLine($"[ETW][AMSI] first event carried no readable text (name={ev}, fields=[{FieldNames(data)}])");
                        return;
                    }
                    AmsiContentSeen = true;
                    _onScriptContent.Invoke(caller, "amsi", content);
                }
                else
                {
                    // Named fields only: PowerShell lifecycle events would otherwise flood the queue.
                    string content = ExtractNamedContent(data, "ScriptBlockText", "Command", "Payload");
                    if (content.Length < MinScriptChars) return;
                    _onScriptContent.Invoke(caller, "powershell", content);
                }
                return;
            }

            uint target = ReadUInt(data, "TargetProcessId", "ProcessId", "TargetPid", "DestPid");
            if (target == 0) target = caller;
            ulong address = ReadUlong(data, "BaseAddress", "AllocationBase", "RegionBase", "Address", "TargetAddress");
            uint protect = ReadUInt(data, "ProtectionMask", "Protection", "NewProtect", "PageProtection", "Win32Protect");
            uint allocType = ReadUInt(data, "AllocationType", "Type");
            ulong size = ReadUlong(data, "RegionSize", "Size", "NumberOfBytes");

            bool allocRwx = IsAllocLike(ev, provider) && IsExecutableProtect(protect);
            bool writeVm = IsWriteLike(ev);
            bool setCtx = IsSetContextLike(ev);
            bool mapView = IsMapViewLike(ev);
            if (!allocRwx && !writeVm && !setCtx && !mapView) return;

            string api = allocRwx ? "VirtualAllocEx"
                : writeVm ? "WriteProcessMemory"
                : setCtx ? "SetThreadContext"
                : "MapViewOfSection";

            var telemetry = new KernelBridge.EtwTiTelemetryEvent
            {
                EventType = 8,
                CallerPid = caller,
                TargetPid = target,
                AllocationBase = address,
                AllocationType = allocRwx ? 1u : writeVm ? 2u : setCtx ? 3u : 4u,
                Protect = protect,
                Size = size
            };
            _onEvent.Invoke(telemetry);

            Console.WriteLine($"[ETW][{api}] caller={caller} target={target} addr=0x{address:X16} prot=0x{protect:X}");
        }
        catch
        {
        }
    }

    private static bool IsExecutableProtect(uint protect)
        => (protect & (PageExecuteReadWrite | PageExecuteWriteCopy | 0x10 | 0x20)) != 0;

    private static bool IsAllocLike(string ev, string provider)
    {
        if (Contains(ev, "AllocVm") || Contains(ev, "VirtualAlloc") || Contains(ev, "AllocateVirtualMemory")) return true;
        if (Contains(ev, "ProtectVm") || Contains(ev, "VirtualProtect") || Contains(ev, "ProtectVirtualMemory")) return true;
        return Contains(provider, "Threat-Intelligence") && Contains(ev, "ALLOC");
    }

    private static bool IsWriteLike(string ev)
        => Contains(ev, "WriteVm") || Contains(ev, "WriteVirtualMemory") || Contains(ev, "WriteProcessMemory");

    private static bool IsSetContextLike(string ev)
        => Contains(ev, "SetContext") || Contains(ev, "SetThreadContext") || Contains(ev, "NtSetContextThread");

    private static bool IsMapViewLike(string ev)
        => Contains(ev, "MapView") || Contains(ev, "MapViewOfSection") || Contains(ev, "NtMapViewOfSection");

    private static bool Contains(string hay, string needle)
        => hay.IndexOf(needle, StringComparison.OrdinalIgnoreCase) >= 0;

    private static uint ReadUInt(TraceEvent data, params string[] names)
    {
        foreach (var n in names)
        {
            object? v = TryPayload(data, n);
            if (v is IConvertible c)
            {
                try { return c.ToUInt32(null); } catch { }
            }
        }
        return 0;
    }

    private static ulong ReadUlong(TraceEvent data, params string[] names)
    {
        foreach (var n in names)
        {
            object? v = TryPayload(data, n);
            if (v is IConvertible c)
            {
                try { return c.ToUInt64(null); } catch { }
            }
        }
        return 0;
    }

    private static object? TryPayload(TraceEvent data, string name)
    {
        try { return data.PayloadByName(name); } catch { return null; }
    }

    private static string ReadStr(TraceEvent data, params string[] names)
    {
        foreach (var n in names)
        {
            object? v = TryPayload(data, n);
            if (v is string s && s.Length > 0) return s;
        }
        return string.Empty;
    }

    /// <summary>
    /// AMSI payloads are not schema-stable across Windows builds, so known field names are
    /// tried first and then the longest string payload wins — the scan text is always the
    /// largest string in the event.
    /// </summary>
    private static string ExtractScriptContent(TraceEvent data)
    {
        string named = ExtractNamedContent(data, "Content", "ScriptContent", "ScanContent", "ScriptBlockText");
        if (named.Length >= MinScriptChars) return Cap(named);

        string longest = string.Empty;
        try
        {
            var names = data.PayloadNames;
            if (names != null)
            {
                int i = 0;
                foreach (var unused in names)
                {
                    object? v = null;
                    try { v = data.PayloadValue(i); } catch { }
                    if (v is string s && s.Length > longest.Length) longest = s;
                    i++;
                }
            }
        }
        catch { }
        return longest.Length >= MinScriptChars ? Cap(longest) : string.Empty;
    }

    private static string ExtractNamedContent(TraceEvent data, params string[] names)
    {
        foreach (var n in names)
        {
            object? v = TryPayload(data, n);
            if (v is string s && s.Length >= MinScriptChars) return Cap(s);
        }
        return string.Empty;
    }

    private static string Cap(string s) => s.Length <= MaxScriptChars ? s : s.Substring(0, MaxScriptChars);

    private static string FieldNames(TraceEvent data)
    {
        try
        {
            var names = data.PayloadNames;
            if (names == null) return "none";
            string joined = string.Join(",", names);
            return joined.Length > 0 ? joined : "none";
        }
        catch { return "unreadable"; }
    }

    private void DisposeSession()
    {
        try { _session?.Dispose(); } catch { }
        _session = null;
    }

    public void Dispose()
    {
        _running = false;
        try { _session?.Stop(); } catch { }
        DisposeSession();
        try { _thread?.Join(500); } catch { }
    }
}
