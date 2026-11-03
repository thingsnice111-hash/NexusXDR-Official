using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;

namespace NexusAV.Engine;

/// <summary>
/// REAL network blocking through the Windows Filtering Platform (fwpuclnt.dll).
/// Unlike the detection-only UserModeNetworkFilter, filters added here are enforced
/// by the tcpip/ale kernel paths — blocked connects genuinely fail. Works from user
/// mode (that is the supported WFP management API); requires elevation.
/// v1 scope: outbound connects (ALE_AUTH_CONNECT v4+v6) by remote IP or by app
/// (ALE_APP_ID). Inbound enforcement would need the RECV_ACCEPT layers.
/// </summary>
public static class WfpBlocker
{
    // Fixed keys so a restarted engine re-adopts its provider/sublayer instead of
    // leaking a new random GUID set every run.
    private static readonly Guid ProviderKey = new("7a3e1c90-2b44-4f1a-9c55-0b3ad7e2a101");
    private static readonly Guid SubLayerKey = new("7a3e1c90-2b44-4f1a-9c55-0b3ad7e2a102");

    private static readonly Guid LayerAleAuthConnectV4 = new("c38d57d1-05a7-4c33-904f-7fbceee60e82");
    private static readonly Guid LayerAleAuthConnectV6 = new("4a72393b-319f-44bc-84c3-ba54dcb3b6b4");
    private static readonly Guid CondIpRemoteAddress = new("b235ae9a-1d64-49b8-a44c-5ff3d9095045");
    private static readonly Guid CondAleAppId = new("d78e1e87-8644-4ea5-9437-d809ecefc971");

    private const uint FwpActionBlock = 0x00001004; // FWP_ACTION_FLAG_TERMINATING | 0x4
    private const int FwpMatchEqual = 0;
    private const int FwpDataTypeEmpty = 0;
    private const int FwpDataTypeByteBlob = 12;   // FWP_BYTE_BLOB_TYPE
    private const int FwpDataTypeV4AddrMask = 0x100; // FWP_V4_ADDR_MASK
    private const int FwpDataTypeV6AddrMask = 0x101; // FWP_V6_ADDR_MASK
    private const uint ErrorAlreadyExists = 0x80320009; // FWP_E_ALREADY_EXISTS

    private static readonly object _gate = new();
    private static IntPtr _engine;
    private static readonly Dictionary<string, List<ulong>> _ipBlocks = new(StringComparer.OrdinalIgnoreCase);
    private static readonly Dictionary<string, List<ulong>> _appBlocks = new(StringComparer.OrdinalIgnoreCase);

    // ── Public API ─────────────────────────────────────────────────────────

    public static string? BlockIp(IPAddress ip)
    {
        string key = ip.ToString();
        lock (_gate)
        {
            if (_ipBlocks.ContainsKey(key)) return null; // already blocked
            if (!EnsureEngine(out var err)) return err;
            var ids = new List<ulong>(2);
            string? fail = null;
            if (ip.AddressFamily == AddressFamily.InterNetwork)
            {
                fail = AddIpFilter(ip, isV6: false, ids);
            }
            else if (ip.AddressFamily == AddressFamily.InterNetworkV6)
            {
                fail = AddIpFilter(ip, isV6: true, ids);
            }
            else
            {
                fail = $"unsupported address family {ip.AddressFamily}";
            }
            if (ids.Count == 0)
            {
                CleanupDead(ids);
                return fail ?? "filter add failed";
            }
            _ipBlocks[key] = ids;
            return null;
        }
    }

    public static string? UnblockIp(IPAddress ip)
    {
        string key = ip.ToString();
        lock (_gate)
        {
            if (!_ipBlocks.TryGetValue(key, out var ids))
                return "not blocked";
            DeleteFilters(ids);
            _ipBlocks.Remove(key);
            return null;
        }
    }

    /// <summary>Block all outbound connects from the image at <paramref name="filePath"/>.</summary>
    public static string? BlockImage(string filePath)
    {
        string key = Path.GetFullPath(filePath);
        lock (_gate)
        {
            if (_appBlocks.ContainsKey(key)) return null;
            if (!EnsureEngine(out var err)) return err;

            uint rc = FwpmGetAppIdFromFileName0(key, out IntPtr blob);
            if (rc != 0 || blob == IntPtr.Zero)
                return $"FwpmGetAppIdFromFileName0 failed 0x{rc:X8} (file not found?)";
            try
            {
                var ids = new List<ulong>(2);
                string? fail = AddAppFilter(blob, ids);
                if (ids.Count == 0) return fail ?? "filter add failed";
                _appBlocks[key] = ids;
                return null;
            }
            finally
            {
                IntPtr p = blob;
                FwpmFreeMemory0(ref p);
            }
        }
    }

    public static string? UnblockImage(string filePath)
    {
        string key = Path.GetFullPath(filePath);
        lock (_gate)
        {
            if (!_appBlocks.TryGetValue(key, out var ids))
                return "not blocked";
            DeleteFilters(ids);
            _appBlocks.Remove(key);
            return null;
        }
    }

    public static int ActiveBlockCount { get { lock (_gate) return _ipBlocks.Count + _appBlocks.Count; } }

    /// <summary>Remove every filter we added (engine shutdown / stop-protection).</summary>
    public static void RemoveAll()
    {
        lock (_gate)
        {
            foreach (var ids in _ipBlocks.Values) DeleteFilters(ids);
            foreach (var ids in _appBlocks.Values) DeleteFilters(ids);
            _ipBlocks.Clear();
            _appBlocks.Clear();
        }
    }

    /// <summary>Close the WFP engine handle. With a dynamic session the kernel also drops every filter we added.</summary>
    public static void Close()
    {
        lock (_gate)
        {
            if (_engine == IntPtr.Zero) return;
            try { FwpmEngineClose0(_engine); } catch { }
            _engine = IntPtr.Zero;
            _ipBlocks.Clear();
            _appBlocks.Clear();
        }
    }

    // ── Filter construction ────────────────────────────────────────────────

    private static string? AddIpFilter(IPAddress ip, bool isV6, List<ulong> ids)
    {
        IntPtr condMem = IntPtr.Zero;
        IntPtr nameMem = IntPtr.Zero;
        IntPtr blobMem = IntPtr.Zero;
        IntPtr pkMem = IntPtr.Zero;
        try
        {
            var cond = new FwpmFilterCondition0();
            cond.FieldKey = CondIpRemoteAddress;
            cond.MatchType = FwpMatchEqual;
            if (!isV6)
            {
                var am = new FwpV4AddrAndMask { Addr = BitConverter.ToUInt32(ip.GetAddressBytes(), 0), Mask = 0xFFFFFFFF };
                blobMem = AllocPinned(am);
                cond.ConditionValue.Type = FwpDataTypeV4AddrMask;
                cond.ConditionValue.ValuePtr = blobMem;
            }
            else
            {
                var am6 = new FwpV6AddrAndMask { Addr = new byte[16] };
                byte[] b = ip.GetAddressBytes();
                Array.Copy(b, am6.Addr, 16);
                am6.PrefixLength = 128;
                blobMem = AllocPinned(am6);
                cond.ConditionValue.Type = FwpDataTypeV6AddrMask;
                cond.ConditionValue.ValuePtr = blobMem;
            }
            condMem = AllocPinned(cond);
            nameMem = AllocName($"NexusAV outbound block ip={ip}");
            pkMem = AllocPinned(ProviderKey);

            var filter = new FwpmFilter0();
            filter.DisplayData.Name = nameMem;
            filter.ProviderKey = pkMem;
            filter.LayerKey = isV6 ? LayerAleAuthConnectV6 : LayerAleAuthConnectV4;
            filter.SubLayerKey = SubLayerKey;
            filter.Weight.Type = FwpDataTypeEmpty;
            filter.NumFilterConditions = 1;
            filter.FilterCondition = condMem;
            filter.Action.Type = FwpActionBlock;
            GCHandle g = GCHandle.Alloc(filter, GCHandleType.Pinned);
            try
            {
                uint rc = FwpmFilterAdd0(_engine, g.AddrOfPinnedObject(), IntPtr.Zero, out ulong id);
                if (rc == 0) { ids.Add(id); return null; }
                return $"FwpmFilterAdd0 failed 0x{rc:X8}";
            }
            finally { g.Free(); }
        }
        finally
        {
            Free(condMem); Free(nameMem); Free(blobMem); Free(pkMem);
        }
    }

    private static string? AddAppFilter(IntPtr appIdBlob, List<ulong> ids)
    {
        IntPtr condsMem = IntPtr.Zero;
        IntPtr nameMem = IntPtr.Zero;
        IntPtr pkMem = IntPtr.Zero;
        try
        {
            int size = Marshal.SizeOf<FwpmFilterCondition0>();
            condsMem = Marshal.AllocHGlobal(size * 2);
            for (int i = 0; i < 2; i++)
            {
                var cond = new FwpmFilterCondition0
                {
                    FieldKey = CondAleAppId,
                    MatchType = FwpMatchEqual,
                    ConditionValue = { Type = FwpDataTypeByteBlob, ValuePtr = appIdBlob }
                };
                Marshal.StructureToPtr(cond, condsMem + i * size, false);
            }
            nameMem = AllocName("NexusAV outbound block app");
            pkMem = AllocPinned(ProviderKey);

            for (int i = 0; i < 2; i++)
            {
                var filter = new FwpmFilter0();
                filter.DisplayData.Name = nameMem;
                filter.ProviderKey = pkMem;
                filter.LayerKey = i == 0 ? LayerAleAuthConnectV4 : LayerAleAuthConnectV6;
                filter.SubLayerKey = SubLayerKey;
                filter.Weight.Type = FwpDataTypeEmpty;
                filter.NumFilterConditions = 1;
                filter.FilterCondition = condsMem + i * size;
                filter.Action.Type = FwpActionBlock;
                GCHandle g = GCHandle.Alloc(filter, GCHandleType.Pinned);
                try
                {
                    uint rc = FwpmFilterAdd0(_engine, g.AddrOfPinnedObject(), IntPtr.Zero, out ulong id);
                    if (rc == 0) ids.Add(id);
                }
                finally { g.Free(); }
            }
            return ids.Count == 2 ? null : "one or both layer filters failed";
        }
        finally
        {
            Free(condsMem); Free(nameMem); Free(pkMem);
        }
    }

    private static void DeleteFilters(List<ulong> ids)
    {
        foreach (var id in ids)
        {
            try { FwpmFilterDeleteById0(_engine, id); } catch { }
        }
        ids.Clear();
    }

    private static void CleanupDead(List<ulong> ids) => ids.Clear();

    // ── Engine / provider / sublayer ───────────────────────────────────────

    private static bool EnsureEngine(out string? error)
    {
        error = null;
        if (_engine != IntPtr.Zero) return true;

        // FWPM_SESSION_FLAG_DYNAMIC (0x1): every filter added through this handle is owned
        // by the session and is deleted by the kernel when the engine process exits — the
        // block can never outlive the engine, even on a crash. Do NOT change this to a
        // persistent session; reboot-surviving firewall state is exactly what we avoid.
        var session = new FwpmSession0 { Flags = 1 };
        GCHandle sh = GCHandle.Alloc(session, GCHandleType.Pinned);
        uint rc;
        try { rc = FwpmEngineOpen0(null, 0, IntPtr.Zero, sh.AddrOfPinnedObject(), out _engine); }
        finally { sh.Free(); }
        if (rc != 0)
        {
            error = $"FwpmEngineOpen0 failed 0x{rc:X8} (admin required)";
            _engine = IntPtr.Zero;
            return false;
        }

        var prov = new FwpmProvider0 { ProviderKey = ProviderKey };
        IntPtr pname = AllocName("NexusAV WFP provider");
        prov.DisplayData.Name = pname;
        GCHandle ph = GCHandle.Alloc(prov, GCHandleType.Pinned);
        try { rc = FwpmProviderAdd0(_engine, ph.AddrOfPinnedObject()); }
        finally { ph.Free(); Free(pname); }
        if (rc != 0 && rc != ErrorAlreadyExists)
        {
            error = $"FwpmProviderAdd0 failed 0x{rc:X8}";
            return false;
        }

        var sub = new FwpmSubLayer0 { SubLayerKey = SubLayerKey, Weight = 0x100 };
        IntPtr sname = AllocName("NexusAV block sublayer");
        IntPtr spk = AllocPinned(ProviderKey);
        sub.DisplayData.Name = sname;
        sub.ProviderKey = spk;
        GCHandle gh = GCHandle.Alloc(sub, GCHandleType.Pinned);
        try { rc = FwpmSubLayerAdd0(_engine, gh.AddrOfPinnedObject()); }
        finally { gh.Free(); Free(sname); Free(spk); }
        if (rc != 0 && rc != ErrorAlreadyExists)
        {
            error = $"FwpmSubLayerAdd0 failed 0x{rc:X8}";
            return false;
        }
        return true;
    }

    // ── Marshalling helpers ────────────────────────────────────────────────

    private static IntPtr AllocPinned<T>(T value) where T : struct
    {
        IntPtr p = Marshal.AllocHGlobal(Marshal.SizeOf<T>());
        Marshal.StructureToPtr(value, p, false);
        return p;
    }

    private static IntPtr AllocName(string s)
    {
        return Marshal.StringToHGlobalUni(s);
    }

    private static void Free(IntPtr p)
    {
        if (p != IntPtr.Zero) Marshal.FreeHGlobal(p);
    }

    // ── Interop ────────────────────────────────────────────────────────────

    [DllImport("fwpuclnt.dll", SetLastError = false)]
    private static extern uint FwpmEngineOpen0([MarshalAs(UnmanagedType.LPWStr)] string? serverName,
        uint authnService, IntPtr authIdentity, IntPtr session, out IntPtr engineHandle);

    [DllImport("fwpuclnt.dll")]
    private static extern void FwpmEngineClose0(IntPtr engineHandle);

    [DllImport("fwpuclnt.dll")]
    private static extern uint FwpmProviderAdd0(IntPtr engine, IntPtr provider);

    [DllImport("fwpuclnt.dll")]
    private static extern uint FwpmSubLayerAdd0(IntPtr engine, IntPtr subLayer);

    [DllImport("fwpuclnt.dll")]
    private static extern uint FwpmFilterAdd0(IntPtr engine, IntPtr filter, IntPtr sd, out ulong id);

    [DllImport("fwpuclnt.dll")]
    private static extern uint FwpmFilterDeleteById0(IntPtr engine, ulong id);

    [DllImport("fwpuclnt.dll", CharSet = CharSet.Unicode)]
    private static extern uint FwpmGetAppIdFromFileName0(string fileName, out IntPtr appId);

    [DllImport("fwpuclnt.dll")]
    private static extern void FwpmFreeMemory0(ref IntPtr p);

    [StructLayout(LayoutKind.Sequential)]
    private struct FwpByteBlob
    {
        public uint Size;
        public IntPtr Data;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct FwpV4AddrAndMask
    {
        public uint Addr;  // host byte order
        public uint Mask;  // host byte order
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct FwpV6AddrAndMask
    {
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
        public byte[] Addr;
        public byte PrefixLength;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct FwpValue0
    {
        public int Type;
        public IntPtr ValuePtr; // union: 8-byte slot covers all scalar/pointer members
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct FwpmDisplayData0
    {
        public IntPtr Name;
        public IntPtr Description;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct FwpmFilterCondition0
    {
        public Guid FieldKey;
        public int MatchType;
        public FwpValue0 ConditionValue;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct FwpmAction0
    {
        public uint Type;
        public Guid CalloutKey;
    }

    // Official layouts per Microsoft Learn (fwpmtypes.h). Field order and
    // by-value-vs-pointer members are ABI-critical — do not reorder.
    [StructLayout(LayoutKind.Sequential)]
    private struct FwpmFilter0
    {
        public Guid FilterKey;
        public FwpmDisplayData0 DisplayData;
        public uint Flags;
        public IntPtr ProviderKey;
        public FwpByteBlob ProviderData;
        public Guid LayerKey;        // by value
        public Guid SubLayerKey;     // by value
        public FwpValue0 Weight;
        public uint NumFilterConditions;
        public IntPtr FilterCondition;
        public FwpmAction0 Action;
        public ulong RawContext;     // union { UINT64 rawContext; GUID providerContextKey; }
        public IntPtr Reserved;
        public ulong FilterId;
        public FwpValue0 EffectiveWeight;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct FwpmProvider0
    {
        public Guid ProviderKey;
        public FwpmDisplayData0 DisplayData;
        public uint Flags;
        public FwpByteBlob ProviderData;
        public ulong ProviderNameTemplate;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct FwpmSubLayer0
    {
        public Guid SubLayerKey;
        public FwpmDisplayData0 DisplayData;
        public ushort Flags;
        public IntPtr ProviderKey;
        public FwpByteBlob ProviderData;
        public ushort Weight;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct FwpmSession0
    {
        public Guid SessionKey;
        public FwpmDisplayData0 DisplayData;
        public uint Flags;
        public uint TxnWaitTimeoutInMSec;
        public uint ProcessId;
        public IntPtr Sid;
        public IntPtr Username;
        public bool KernelMode;
    }
}
