using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32;

namespace NexusAV.Engine;

public sealed class WifiSeekerFinding
{
    public required string Source;
    public required string Detail;
    public int Score;
}

/// <summary>
/// Sensor for C2-like Wi-Fi activity: hardware RF seekers (USB monitor adapters) plus OS WLAN scan.
/// Findings are reported only — this class never cuts the network and holds no driver handle.
/// </summary>
public sealed unsafe partial class WifiSeekerC2Shield : IDisposable
{
    private static readonly string[] SeekerHints =
    {
        "HACKRF", "RTL2832", "RTLSDR", "AIRPCAP", "AWUS", "ALFA NETWORK",
        "PINEAPPLE", "UBERTOOTH", "YARDSTICK", "HAK5", "WIFI SEEKER",
        "PACKET SNIFFER", "ATH9K_HTC", "RTL8812", "RTL8814", "MONITOR"
    };

    private static readonly string[] C2SsidHints =
    {
        "C2-", "C2_", "CMD-", "BEACON", "EMPIRE", "COBALT", "SLIVER",
        "METASPLOIT", "HAVOC", "MYTHIC", "NIGHTHAWK"
    };

    // WLAN_AVAILABLE_NETWORK (wlanapi.h) is 628 bytes: strProfileName[256] 0..511,
    // dot11Ssid.uSSIDLength at 512, ucSSID at 516, wlanSignalQuality (0-100 %) at 604, dwFlags at 620.
    private const int NetRecSize = 628;
    private const int SsidLenOff = 512;
    private const int SsidOff = 516;
    private const int SignalQualityOff = 604;

    private readonly Storyteller _story;
    private Thread? _thread;
    private int _disposed;
    private int _seekerHardwareCount;
    private readonly List<WifiSeekerFinding> _findings = new();
    private readonly object _lock = new();

    public int SeekerHardwareCount => Volatile.Read(ref _seekerHardwareCount);
    public IReadOnlyList<WifiSeekerFinding> Findings
    {
        get { lock (_lock) return _findings.ToArray(); }
    }

    public WifiSeekerC2Shield(Storyteller story)
    {
        _story = story;
    }

    public int ProbeHardware()
    {
        int n = 0;
        try
        {
            using RegistryKey? usb = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Enum\USB");
            if (usb != null)
            {
                foreach (string vid in usb.GetSubKeyNames())
                {
                    using RegistryKey? vidKey = usb.OpenSubKey(vid);
                    if (vidKey == null) continue;
                    foreach (string inst in vidKey.GetSubKeyNames())
                    {
                        using RegistryKey? instKey = vidKey.OpenSubKey(inst);
                        string desc = Convert.ToString(instKey?.GetValue("DeviceDesc") ?? instKey?.GetValue("FriendlyName") ?? "") ?? "";
                        string loc = Convert.ToString(instKey?.GetValue("LocationInformation") ?? "") ?? "";
                        string blob = (vid + " " + desc + " " + loc).ToUpperInvariant();
                        foreach (string h in SeekerHints)
                        {
                            if (blob.Contains(h, StringComparison.Ordinal))
                            {
                                n++;
                                Console.WriteLine($"[WIFI-SEEKER] hardware sensor: {desc} ({vid})");
                                break;
                            }
                        }
                    }
                }
            }
        }
        catch { }
        Volatile.Write(ref _seekerHardwareCount, n);
        if (n == 0)
            Console.WriteLine("[WIFI-SEEKER] no dedicated RF seeker; using OS WLAN scan as sensor.");
        return n;
    }

    public void Start()
    {
        ObjectDisposedException.ThrowIf(_disposed == 1, this);
        ProbeHardware();
        if (_thread != null) return;
        _thread = new Thread(Loop) { Name = "Nexus-WifiSeeker", IsBackground = true, Priority = ThreadPriority.BelowNormal };
        _thread.Start();
    }

    private void Loop()
    {
        while (Volatile.Read(ref EngineState.ShuttingDown) == 0 && Volatile.Read(ref _disposed) == 0)
        {
            try { ScanOnce(); }
            catch (Exception ex) { Console.WriteLine($"[WIFI-SEEKER] scan error: {ex.Message}"); }
            Thread.Sleep(15_000);
        }
    }

    public int ScanOnce()
    {
        var hits = new List<WifiSeekerFinding>();
        ScanWlan(hits);
        int score = 0;
        foreach (var h in hits) score += h.Score;
        lock (_lock)
        {
            _findings.Clear();
            _findings.AddRange(hits);
        }
        if (hits.Count > 0)
        {
            foreach (var h in hits)
                Console.WriteLine($"[C2-SHIELD][WIFI] {h.Source}: {h.Detail} score={h.Score}");
            _story.ReportWifiC2(score, hits.Count);
            // Sensor only: even a confident score is reported, never acted on. Cutting the
            // network on a Wi-Fi heuristic would take the machine offline on a false positive.
            EventBus.Status($"wifi_c2 score={score} hits={hits.Count} action=log-only");
        }
        return hits.Count;
    }

    private static void ScanWlan(List<WifiSeekerFinding> hits, List<string>? dump = null)
    {
        nint client = 0;
        try
        {
            uint st = WlanOpenHandle(2, nint.Zero, out uint _, out client);
            if (st != 0 || client == 0) return;
            st = WlanEnumInterfaces(client, nint.Zero, out nint listPtr);
            if (st != 0 || listPtr == 0) return;
            uint count = (uint)Marshal.ReadInt32(listPtr);
            int header = IntPtr.Size == 8 ? 8 : 4;
            for (uint i = 0; i < count && i < 8; i++)
            {
                // WLAN_INTERFACE_INFO_LIST: 8-byte header, then 532-byte WLAN_INTERFACE_INFO records.
                nint iface = listPtr + header + (nint)(i * 532);
                Guid guid = Marshal.PtrToStructure<Guid>(iface);
                _ = WlanScan(client, ref guid, nint.Zero, nint.Zero, nint.Zero);
                Thread.Sleep(400);
                if (WlanGetAvailableNetworkList(client, ref guid, 3, nint.Zero, out nint netList) != 0 || netList == 0)
                    continue;
                // dwNumberOfItems sits at +0; +4 is dwIndex and is always 0 here.
                uint netCount = (uint)Marshal.ReadInt32(netList);
                nint first = netList + 8;
                for (uint n = 0; n < netCount && n < 64; n++)
                {
                    nint rec = first + (nint)(n * NetRecSize);
                    int ssidLen = (int)Math.Min((uint)Marshal.ReadInt32(rec + SsidLenOff), 32u);
                    byte[] ssidBytes = new byte[ssidLen];
                    Marshal.Copy(rec + SsidOff, ssidBytes, 0, ssidLen);
                    string ssid = Encoding.UTF8.GetString(ssidBytes);
                    bool hidden = ssidLen == 0;
                    int signalQuality = Marshal.ReadInt32(rec + SignalQualityOff);
                    dump?.Add($"{(hidden ? "(hidden)" : ssid)} q={signalQuality} hidden={hidden}");

                    int score = 0;
                    string why = ssid;
                    if (hidden) { score += 25; why = "(hidden SSID)"; }
                    string up = ssid.ToUpperInvariant();
                    foreach (string h in C2SsidHints)
                    {
                        if (up.Contains(h, StringComparison.Ordinal))
                        {
                            score += 50;
                            why = ssid;
                            break;
                        }
                    }
                    if (ssid.Length >= 20 && LooksRandom(ssid)) { score += 20; }
                    // signalQuality is a 0-100 percentage, not dBm: >=90 means the AP is very close.
                    if (signalQuality >= 90 && hidden) score += 10;
                    if (score >= 20)
                        hits.Add(new WifiSeekerFinding { Source = "WLAN", Detail = why, Score = score });
                }
                WlanFreeMemory(netList);
            }
            WlanFreeMemory(listPtr);
        }
        catch { }
        finally
        {
            if (client != 0) WlanCloseHandle(client, nint.Zero);
        }
    }

    // Headless parse check: decodes the visible networks so the offsets above can be
    // compared against `netsh wlan show networks`. Sensor only, never acts.
    internal static int SelfTestWlan()
    {
        var hits = new List<WifiSeekerFinding>();
        var dump = new List<string>();
        ScanWlan(hits, dump);
        foreach (string row in dump) Console.WriteLine($"[WIFI-SELFTEST] net {row}");
        foreach (var h in hits) Console.WriteLine($"[WIFI-SELFTEST] finding score={h.Score} {h.Detail}");
        Console.WriteLine($"[WIFI-SELFTEST] parsed={dump.Count} findings={hits.Count} action=log-only");
        return hits.Count;
    }

    private static bool LooksRandom(string s)
    {
        int hex = 0;
        foreach (char c in s)
        {
            if (char.IsAsciiHexDigit(c)) hex++;
        }
        return hex * 2 >= s.Length;
    }

    [LibraryImport("wlanapi.dll")]
    private static partial uint WlanOpenHandle(uint dwClientVersion, nint pReserved, out uint pdwNegotiatedVersion, out nint phClientHandle);

    [LibraryImport("wlanapi.dll")]
    private static partial uint WlanCloseHandle(nint hClientHandle, nint pReserved);

    [LibraryImport("wlanapi.dll")]
    private static partial uint WlanEnumInterfaces(nint hClientHandle, nint pReserved, out nint ppInterfaceList);

    [LibraryImport("wlanapi.dll")]
    private static partial uint WlanScan(nint hClientHandle, ref Guid pInterfaceGuid, nint pDot11Ssid, nint pIeData, nint pReserved);

    [LibraryImport("wlanapi.dll")]
    private static partial uint WlanGetAvailableNetworkList(nint hClientHandle, ref Guid pInterfaceGuid, uint dwFlags, nint pReserved, out nint ppAvailableNetworkList);

    [LibraryImport("wlanapi.dll")]
    private static partial void WlanFreeMemory(nint pMemory);

    public void Dispose()
    {
        if (Interlocked.CompareExchange(ref _disposed, 1, 0) != 0) return;
        _thread?.Join(500);
    }
}
