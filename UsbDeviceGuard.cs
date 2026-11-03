using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;

namespace NexusAV.Engine;

/// <summary>
/// Per-device USB storage control via the Plug-and-Play configuration manager (CfgMgr32).
///
/// Safety design (deliberately NOT the global `USBSTOR\Start=4` sledgehammer):
///  - Block/unblock acts on ONE device instance (CM_Disable_DevNode / CM_Enable_DevNode),
///    never on the USBSTOR service or any other enumerator.
///  - Every devnode we disable is recorded in a state file and RE-ENABLED on engine
///    shutdown and on the next engine start (unclean-shutdown recovery), so the block can
///    never outlive the engine without a working undo.
///  - Arrival/removal of USB storage devices is detected by enumerator diffing and
///    reported as real events (badge for BadUSB-style prompt alerts), with a baseline
///    taken at engine start.
/// </summary>
public sealed class UsbDeviceGuard : IDisposable
{
    public sealed record DeviceInfo(string InstanceId, string Vendor, string Product, string State, bool BlockedByUs);
    public sealed record ActionResult(bool Ok, string State, string Message);

    private const string UsbStorEnumerator = "USBSTOR";
    private const uint CmGetIdListFilterEnumerator = 0x00000001;
    private const uint CrSuccess = 0;
    private const uint DnHasProblem = 0x00000400;
    private const uint CmProbDisabled = 22;

    private readonly StorytellerStable _feed;
    private readonly string _statePath;
    private readonly HashSet<string> _known = new(StringComparer.OrdinalIgnoreCase);
    private readonly HashSet<string> _blockedByUs = new(StringComparer.OrdinalIgnoreCase);
    private readonly object _lock = new();
    private readonly Thread _thread;
    private readonly CancellationTokenSource _cts = new();
    private bool _firstPass = true;
    private int _disposed;

    public UsbDeviceGuard(StorytellerStable feed)
    {
        _feed = feed;
        string dir = NexusDataDir.Root;
        try { NexusDataDir.Ensure(); } catch { }
        _statePath = Path.Combine(dir, "usb_disabled.txt");
        _thread = new Thread(Loop) { IsBackground = true, Name = "Nexus-UsbGuard", Priority = ThreadPriority.BelowNormal };
    }

    public void Start()
    {
        RecoverPreviouslyDisabled();
        _thread.Start();
    }

    // ── Undo-the-undo: re-enable anything a previous (possibly crashed) engine disabled ──
    private void RecoverPreviouslyDisabled()
    {
        try
        {
            if (!File.Exists(_statePath)) return;
            foreach (string line in File.ReadAllLines(_statePath))
            {
                string id = line.Trim();
                if (id.Length == 0) continue;
                var r = SetEnabled(id, enable: true);
                Console.WriteLine($"[USB] session recovery: re-enable {id} -> {(r.Ok ? "ok" : r.Message)}");
            }
            File.Delete(_statePath);
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[USB] session recovery failed: {ex.Message}");
        }
    }

    private void Loop()
    {
        while (Volatile.Read(ref EngineState.ShuttingDown) == 0 && !_cts.IsCancellationRequested)
        {
            try { PollDevices(); }
            catch (Exception ex) { Console.WriteLine($"[USB] poll fault (non-fatal): {ex.Message}"); }
            try { _cts.Token.WaitHandle.WaitOne(2000); } catch { }
        }
    }

    private void PollDevices()
    {
        var devices = EnumerateDevices();
        lock (_lock)
        {
            foreach (var d in devices)
            {
                if (_known.Contains(d.InstanceId)) continue;
                _known.Add(d.InstanceId);
                if (!_firstPass)
                {
                    string ven = d.Vendor.Length > 0 ? d.Vendor : "unknown vendor";
                    Console.WriteLine($"[USB] device arrived: {d.InstanceId} ({ven} {d.Product}) state={d.State}");
                    Publish("arrival", d, true, "USB storage device connected");
                    _feed.AddUsbDevice("arrival", d.InstanceId, d.State, $"{ven} {d.Product} connected");
                }
            }
            if (!_firstPass)
            {
                List<string>? gone = null;
                foreach (var id in _known)
                {
                    bool present = false;
                    foreach (var d in devices) { if (d.InstanceId.Equals(id, StringComparison.OrdinalIgnoreCase)) { present = true; break; } }
                    if (!present) (gone ??= new List<string>()).Add(id);
                }
                if (gone != null)
                {
                    foreach (string id in gone)
                    {
                        _known.Remove(id);
                        Console.WriteLine($"[USB] device removed: {id}");
                        Publish("removal", new DeviceInfo(id, "", "", "absent", false), true, "USB storage device disconnected");
                    }
                }
            }
            _firstPass = false;
        }
    }

    // ── Commands ────────────────────────────────────────────────────────────

    public void PublishStatus()
    {
        var devices = EnumerateDevices();
        var sb = new StringBuilder(512);
        sb.Append("{\"t\":\"usbdev\",\"op\":\"list\",\"ok\":true,\"count\":").Append(devices.Count).Append(",\"devs\":[");
        for (int i = 0; i < devices.Count; i++)
        {
            if (i > 0) sb.Append(',');
            var d = devices[i];
            sb.Append("{\"id\":").Append(J.Str(d.InstanceId))
              .Append(",\"ven\":").Append(J.Str(d.Vendor))
              .Append(",\"prod\":").Append(J.Str(d.Product))
              .Append(",\"state\":").Append(J.Str(d.State))
              .Append(",\"ours\":").Append(d.BlockedByUs ? "true" : "false")
              .Append('}');
        }
        sb.Append("]}");
        EventBus.Publish(sb.ToString());
    }

    public ActionResult Block(string instanceId)
    {
        if (!IsUsbStorInstance(instanceId))
            return new ActionResult(false, "unknown", "only USBSTOR device instances can be blocked (got '" + instanceId + "')");
        var r = SetEnabled(instanceId, enable: false);
        if (r.Ok)
        {
            lock (_lock) _blockedByUs.Add(instanceId);
            SaveState();
            Publish("blocked", Describe(instanceId), true, "device disabled — re-enabled automatically on engine stop");
            _feed.AddUsbDevice("blocked", instanceId, "disabled", "per-device block (auto-reverted on engine stop)");
        }
        else
        {
            Publish("blocked", Describe(instanceId), false, r.Message);
        }
        return r;
    }

    public ActionResult Unblock(string instanceId)
    {
        if (!IsUsbStorInstance(instanceId))
            return new ActionResult(false, "unknown", "only USBSTOR device instances can be unblocked");
        var r = SetEnabled(instanceId, enable: true);
        if (r.Ok)
        {
            lock (_lock) _blockedByUs.Remove(instanceId);
            SaveState();
            Publish("unblocked", Describe(instanceId), true, "device enabled");
            _feed.AddUsbDevice("unblocked", instanceId, "active", "device re-enabled");
        }
        else
        {
            Publish("unblocked", Describe(instanceId), false, r.Message);
        }
        return r;
    }

    private static bool IsUsbStorInstance(string id) =>
        !string.IsNullOrEmpty(id) && id.StartsWith(UsbStorEnumerator + "\\", StringComparison.OrdinalIgnoreCase);

    private ActionResult SetEnabled(string instanceId, bool enable)
    {
        uint cr = CmLocateDevNode(out uint devInst, instanceId, 0);
        if (cr != CrSuccess)
            return new ActionResult(false, "unknown", $"CM_Locate_DevNode 0x{cr:X} for {instanceId}");

        cr = enable ? CmEnableDevNode(devInst, 0) : CmDisableDevNode(devInst, 0);
        if (cr == CrSuccess)
            return new ActionResult(true, enable ? "active" : "disabled",
                enable ? "device enabled" : "device disabled");

        string hint = cr == 0x33 ? " (access denied — run the engine as Administrator)" : $" (cfg 0x{cr:X})";
        return new ActionResult(false, "error", (enable ? "CM_Enable_DevNode" : "CM_Disable_DevNode") + " failed" + hint);
    }

    private void SaveState()
    {
        try
        {
            lock (_lock)
            {
                if (_blockedByUs.Count == 0)
                {
                    if (File.Exists(_statePath)) File.Delete(_statePath);
                    return;
                }
                File.WriteAllLines(_statePath, _blockedByUs);
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[USB] failed to persist block state: {ex.Message}");
        }
    }

    // ── Enumeration ─────────────────────────────────────────────────────────

    private List<DeviceInfo> EnumerateDevices()
    {
        var list = new List<DeviceInfo>(4);
        IntPtr buf = IntPtr.Zero;
        try
        {
            // REG_MULTI_SZ filter needs a double terminator ("USBSTOR\0" + managed marshaler's null).
            string filter = UsbStorEnumerator + "\0";
            uint cr = CmGetDeviceIdListSize(out uint len, filter, CmGetIdListFilterEnumerator);
            if (cr != CrSuccess || len == 0) return list;

            buf = Marshal.AllocHGlobal((int)(len * 2));
            cr = CmGetDeviceIdList(filter, buf, len, CmGetIdListFilterEnumerator);
            if (cr != CrSuccess) return list;

            IntPtr p = buf;
            while (true)
            {
                string? id = Marshal.PtrToStringUni(p);
                if (string.IsNullOrEmpty(id)) break;
                list.Add(Describe(id));
                p = IntPtr.Add(p, (id.Length + 1) * 2);
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[USB] enumeration failed: {ex.Message}");
        }
        finally
        {
            if (buf != IntPtr.Zero) Marshal.FreeHGlobal(buf);
        }
        return list;
    }

    private DeviceInfo Describe(string instanceId)
    {
        string state = "unknown";
        if (CmLocateDevNode(out uint devInst, instanceId, 0) == CrSuccess)
        {
            if (CmGetDevNodeStatus(out uint status, out uint problem, devInst, 0) == CrSuccess)
            {
                bool disabled = (status & DnHasProblem) != 0 && problem == CmProbDisabled;
                state = disabled ? "disabled" : "active";
            }
        }
        bool ours = false;
        lock (_lock) ours = _blockedByUs.Contains(instanceId);
        ParseVendorProduct(instanceId, out string vendor, out string product);
        return new DeviceInfo(instanceId, vendor, product, state, ours);
    }

    private static void ParseVendorProduct(string instanceId, out string vendor, out string product)
    {
        vendor = ""; product = "";
        try
        {
            int ven = instanceId.IndexOf("Ven_", StringComparison.OrdinalIgnoreCase);
            if (ven >= 0)
            {
                int end = instanceId.IndexOf('&', ven);
                vendor = (end > ven ? instanceId.Substring(ven + 4, end - ven - 4) : instanceId.Substring(ven + 4)).Replace('_', ' ');
            }
            int prod = instanceId.IndexOf("Prod_", StringComparison.OrdinalIgnoreCase);
            if (prod >= 0)
            {
                int end = instanceId.IndexOf('&', prod);
                product = (end > prod ? instanceId.Substring(prod + 5, end - prod - 5) : instanceId.Substring(prod + 5)).Replace('_', ' ');
            }
        }
        catch { }
    }

    private static void Publish(string op, DeviceInfo d, bool ok, string msg)
    {
        var sb = new StringBuilder(192);
        sb.Append("{\"t\":\"usbdev\",\"op\":").Append(J.Str(op))
          .Append(",\"id\":").Append(J.Str(d.InstanceId))
          .Append(",\"ven\":").Append(J.Str(d.Vendor))
          .Append(",\"prod\":").Append(J.Str(d.Product))
          .Append(",\"state\":").Append(J.Str(d.State))
          .Append(",\"ok\":").Append(ok ? "true" : "false")
          .Append(",\"msg\":").Append(J.Str(msg))
          .Append(",\"ts\":").Append(DateTimeOffset.UtcNow.ToUnixTimeMilliseconds())
          .Append('}');
        EventBus.Publish(sb.ToString());
    }

    public void Dispose()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0) return;
        try { _cts.Cancel(); } catch { }
        try { _thread.Join(1500); } catch { }

        // Engine is stopping: re-enable every device we disabled (the block must never
        // outlive the engine), then clear the state file.
        List<string> pending;
        lock (_lock) pending = new List<string>(_blockedByUs);
        foreach (string id in pending)
        {
            var r = SetEnabled(id, enable: true);
            Console.WriteLine($"[USB] shutdown: re-enable {id} -> {(r.Ok ? "ok" : r.Message)}");
        }
        lock (_lock) _blockedByUs.Clear();
        SaveState();
    }

    // ── Interop (cfgmgr32) ──────────────────────────────────────────────────

    [DllImport("cfgmgr32.dll", CharSet = CharSet.Unicode, EntryPoint = "CM_Get_Device_ID_List_SizeW")]
    private static extern uint CmGetDeviceIdListSize(out uint pulLen, string filter, uint flags);

    [DllImport("cfgmgr32.dll", CharSet = CharSet.Unicode, EntryPoint = "CM_Get_Device_ID_ListW")]
    private static extern uint CmGetDeviceIdList(string filter, IntPtr buffer, uint bufferLen, uint flags);

    [DllImport("cfgmgr32.dll", CharSet = CharSet.Unicode, EntryPoint = "CM_Locate_DevNodeW")]
    private static extern uint CmLocateDevNode(out uint pdnDevInst, string pDeviceID, uint ulFlags);

    [DllImport("cfgmgr32.dll", EntryPoint = "CM_Get_DevNode_Status")]
    private static extern uint CmGetDevNodeStatus(out uint pulStatus, out uint pulProblemNumber, uint dnDevInst, uint ulFlags);

    [DllImport("cfgmgr32.dll", EntryPoint = "CM_Disable_DevNode")]
    private static extern uint CmDisableDevNode(uint dnDevInst, uint ulFlags);

    [DllImport("cfgmgr32.dll", EntryPoint = "CM_Enable_DevNode")]
    private static extern uint CmEnableDevNode(uint dnDevInst, uint ulFlags);
}
