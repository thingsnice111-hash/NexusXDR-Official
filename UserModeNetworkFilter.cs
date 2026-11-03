using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;

namespace NexusAV.Engine;

/// <summary>
/// Connection-level network monitoring: watches the live TCP owner table, flags
/// connections to known backdoor ports / explicitly blocked IPs, and tracks data
/// volumes. Enforcement is REAL — blocked connections go through <see cref="WfpBlocker"/>
/// (dynamic-session WFP filters that die with the engine process), never through
/// persistent firewall rules.
/// </summary>
public sealed class UserModeNetworkFilter : IDisposable
{
    private readonly ConcurrentDictionary<uint, List<NetworkConnection>> _processConnections = new();
    private readonly ConcurrentDictionary<IPAddress, byte> _blockedIPs = new();
    private readonly ConcurrentDictionary<uint, int> _suspiciousProcessScores = new();
    private readonly Timer _monitorTimer;
    private readonly CancellationTokenSource _cts = new();
    private readonly Task _monitorTask;
    private volatile bool _isRunning;
    private int _disposed;
    private int _connectionsBlocked;

    // Backdoor / post-exploitation listener ports that legit software almost never uses.
    private static readonly int[] SuspiciousPorts = { 4444, 6666, 31337 };

    // A process's connection bookkeeping is a display aid, not a ledger of every socket the
    // machine ever opened; without a cap a browser left running for a day grew this unbounded.
    private const int MaxRecordsPerProcess = 512;

    // A process talking to more than this many distinct addresses in a single 1 s pass is doing
    // something no normal app does (scanning, worming, chunked exfiltration).
    private const int ExfilDistinctPeerThreshold = 80;

    // Distinct remote peers seen for each pid in the latest TCP-table pass.
    private volatile Dictionary<uint, int> _passPeerCounts = new();
    private readonly ConcurrentDictionary<uint, int> _exfilReported = new();

    public record NetworkConnection(
        uint Pid,
        string ProcessName,
        IPAddress RemoteIP,
        int RemotePort,
        string Protocol,
        DateTime Timestamp,
        bool WasBlocked,
        string Reason
    );

    public event Action<uint, string, string>? OnSuspiciousConnection;
    public event Action<uint, string>? OnConnectionBlocked;

    public UserModeNetworkFilter()
    {
        _monitorTimer = new Timer(MonitorNetwork, null, TimeSpan.FromSeconds(1), TimeSpan.FromSeconds(1));
        _monitorTask = Task.Run(MonitorLoop);
    }

    public void Start()
    {
        _isRunning = true;
        Console.WriteLine("[NETWORK-FILTER] Connection monitor started");
        Console.WriteLine("[NETWORK-FILTER] Features:");
        Console.WriteLine("  - Real-time TCP table monitoring");
        Console.WriteLine("  - Backdoor-port / blocked-IP flagging");
        Console.WriteLine("  - Data exfiltration volume tracking");
        Console.WriteLine("  - Real enforcement via WFP dynamic session (filters die with the engine)");
    }

    public void Stop()
    {
        _isRunning = false;
        _cts.Cancel();

        // Lift every WFP block we applied (the dynamic session would also drop them on
        // process exit, but a clean stop must not leave the host with live filters).
        foreach (var ip in _blockedIPs.Keys)
        {
            string? err = WfpBlocker.UnblockIp(ip);
            if (err == null)
                Console.WriteLine($"[NETWORK-FILTER] Unblocked {ip} (engine stopping)");
        }
        _blockedIPs.Clear();

        Console.WriteLine("[NETWORK-FILTER] Network filtering stopped");
    }

    private async void MonitorLoop()
    {
        while (!_cts.IsCancellationRequested)
        {
            try
            {
                if (_isRunning)
                {
                    await DetectDataExfiltration();
                }
                await Task.Delay(1000, _cts.Token);
            }
            catch (OperationCanceledException)
            {
                break;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[NETWORK-FILTER] Monitor loop error: {ex.Message}");
            }
        }
    }

    private void MonitorNetwork(object? state)
    {
        if (!_isRunning) return;

        try
        {
            // Get active network connections with PID mapping
            var connections = GetExtendedTcpTable();
            
            // Per-pass peer sets: the exfiltration heuristic has to measure CURRENT sockets.
            // _processConnections only ever grew, so any long-lived browser eventually crossed
            // the old threshold and looked like an implant.
            var passPeers = new Dictionary<uint, HashSet<IPAddress>>();

            foreach (var conn in connections)
            {
                try
                {
                    uint pid = conn.ProcessId;
                    if (pid > 0 && pid != 4) // Skip System
                    {
                        IPAddress remoteIP = new IPAddress(conn.RemoteAddr);
                        if (conn.RemoteAddr == 0) continue;   // listener row, no remote peer
                        int remotePort = conn.RemotePort;

                        if (!passPeers.TryGetValue(pid, out var peers))
                            passPeers[pid] = peers = new HashSet<IPAddress>();
                        peers.Add(remoteIP);

                        // Check if connection is suspicious
                        bool isSuspicious = IsSuspiciousConnection(remoteIP, remotePort);
                        string reason = isSuspicious ? GetSuspicionReason(remoteIP, remotePort) : "Normal";
                        
                        if (!_processConnections.TryGetValue(pid, out var known))
                            _processConnections[pid] = known = new List<NetworkConnection>();

                        bool seenBefore = false;
                        for (int i = 0; i < known.Count; i++)
                        {
                            if (known[i].RemoteIP.Equals(remoteIP) && known[i].RemotePort == remotePort)
                            { seenBefore = true; break; }
                        }
                        if (seenBefore) continue;

                        try
                        {
                            string procName = "unknown";
                            try { using var p = Process.GetProcessById((int)pid); procName = p.ProcessName; }
                            catch { }

                            var connection = new NetworkConnection(
                                pid, procName, remoteIP, remotePort, "TCP", DateTime.Now, false, reason);

                            if (isSuspicious)
                            {
                                // Every new suspicious endpoint raises this process's score, so the
                                // gate below is reachable: a process that touches two backdoor/C2
                                // endpoints is no longer given the benefit of the doubt.
                                int score = _suspiciousProcessScores.AddOrUpdate(pid, 25, (k, v) => Math.Min(100, v + 25));
                                OnSuspiciousConnection?.Invoke(pid, remoteIP.ToString(), reason);

                                // Nothing legitimate connects OUT to 4444/6666/31337, so the first
                                // sighting blocks it. Waiting for a score that only a 100+ socket
                                // process could reach made this module a pure notifier. The filter
                                // is one outbound IP, WFP dynamic-session scoped to the engine's own
                                // lifetime, and lifted on Stop() — a wrong call costs one connection.
                                bool backdoorPort = SuspiciousPorts.Contains(remotePort);
                                if (backdoorPort || score >= 50)
                                {
                                    if (BlockConnection(pid, remoteIP, remotePort, reason))
                                    {
                                        connection = connection with { WasBlocked = true };
                                        OnConnectionBlocked?.Invoke(pid, remoteIP.ToString());
                                        Interlocked.Increment(ref _connectionsBlocked);
                                        EventBus.Status($"net_blocked pid={pid} img={procName} ip={remoteIP} port={remotePort} reason={reason} score={score}");
                                    }
                                }
                            }

                            if (known.Count < MaxRecordsPerProcess) known.Add(connection);
                        }
                        catch { }
                    }
                }
                catch
                {
                    // Connection may have closed
                }
            }

            _passPeerCounts = passPeers.ToDictionary(kv => kv.Key, kv => kv.Value.Count);
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[NETWORK-FILTER] Network monitor error: {ex.Message}");
        }
    }

    private List<TcpRow> GetExtendedTcpTable()
    {
        var result = new List<TcpRow>();
        try
        {
            int size = 0;
            int ret = GetExtendedTcpTable(IntPtr.Zero, ref size, false, AF_INET, TCP_TABLE_OWNER_PID_ALL);
            if (ret != 0) return result;

            IntPtr table = Marshal.AllocHGlobal(size);
            try
            {
                ret = GetExtendedTcpTable(table, ref size, false, AF_INET, TCP_TABLE_OWNER_PID_ALL);
                if (ret != 0) return result;

                int rowSize = Marshal.SizeOf<TcpRow>();
                int numEntries = (size - Marshal.SizeOf<int>()) / rowSize;
                IntPtr rowPtr = table + Marshal.SizeOf<int>();

                for (int i = 0; i < numEntries; i++)
                {
                    var row = Marshal.PtrToStructure<TcpRow>(rowPtr);
                    result.Add(row);
                    rowPtr += rowSize;
                }
            }
            finally
            {
                Marshal.FreeHGlobal(table);
            }
        }
        catch { }
        return result;
    }

    private const int AF_INET = 2;
    private const int TCP_TABLE_OWNER_PID_ALL = 5;

    [StructLayout(LayoutKind.Sequential)]
    private struct TcpRow
    {
        public uint State;
        public uint LocalAddr;
        public byte LocalPort1;
        public byte LocalPort2;
        public byte LocalPort3;
        public byte LocalPort4;
        public uint RemoteAddr;
        public byte RemotePort1;
        public byte RemotePort2;
        public byte RemotePort3;
        public byte RemotePort4;
        public uint OwningPid;
        public ushort Padding;

        public int LocalPort => LocalPort1 << 8 | LocalPort2;
        public int RemotePort => RemotePort1 << 8 | RemotePort2;
        public uint ProcessId => OwningPid;
    }

    [DllImport("iphlpapi.dll", SetLastError = true)]
    private static extern int GetExtendedTcpTable(IntPtr pTcpTable, ref int pdwSize, [MarshalAs(UnmanagedType.Bool)] bool bOrder, uint ulAf, int TableClass);

    private bool IsSuspiciousConnection(IPAddress remoteIP, int remotePort)
    {
        if (_blockedIPs.ContainsKey(remoteIP))
            return true;

        return SuspiciousPorts.Contains(remotePort);
    }

    private string GetSuspicionReason(IPAddress remoteIP, int remotePort)
    {
        if (_blockedIPs.ContainsKey(remoteIP))
            return "Blocked IP";
        if (SuspiciousPorts.Contains(remotePort))
            return $"Backdoor-port {remotePort}";
        return "Unknown";
    }

    private async Task DetectDataExfiltration()
    {
        try
        {
            // Fan-out over DISTINCT peers in the current pass. The old check counted lifetime
            // connections per pid, which a browser crosses during a normal page load, and its
            // score could only ever be reached after >100 sockets — so it reported noise and
            // blocked nothing.
            var snapshot = _passPeerCounts;
            foreach (var (pid, peers) in snapshot)
            {
                if (peers <= ExfilDistinctPeerThreshold) continue;

                Console.WriteLine($"[NETWORK-FILTER] PEER FAN-OUT SUSPECTED: pid={pid} talks to {peers} distinct remote addresses right now");
                int score = _suspiciousProcessScores.AddOrUpdate(pid, 30, (k, v) => Math.Min(100, v + 30));

                // Report each escalation once, not on every 1 s pass.
                int lastReported = _exfilReported.TryGetValue(pid, out int lr) ? lr : 0;
                if (score > lastReported)
                {
                    _exfilReported[pid] = score;
                    EventBus.Detection("network", "audit", "Possible data exfiltration pattern",
                        $"pid={pid} holds {peers} distinct outbound peers in one pass (score {score})", pid);
                }
            }

            if (_suspiciousProcessScores.Count > 4096) _suspiciousProcessScores.Clear();
            if (_exfilReported.Count > 4096) _exfilReported.Clear();
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[NETWORK-FILTER] Data exfiltration detection error: {ex.Message}");
        }
        await Task.CompletedTask;
    }

    private bool BlockConnection(uint pid, IPAddress ip, int port, string reason)
    {
        try
        {
            // Real enforcement: a WFP ALE_AUTH_CONNECT block filter via the dynamic session
            // in WfpBlocker. Returns null on success (or if already blocked).
            string? err = WfpBlocker.BlockIp(ip);
            if (err != null)
            {
                Console.WriteLine($"[NETWORK-FILTER] WFP block failed for {ip}: {err}");
                return false;
            }
            _blockedIPs.TryAdd(ip, 0);
            Console.WriteLine($"[NETWORK-FILTER] Blocked via WFP: pid={pid} ip={ip} port={port} reason={reason}");
            return true;
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[NETWORK-FILTER] Failed to block connection: {ex.Message}");
            return false;
        }
    }

    /// <summary>Block an IP through WFP (used by the GUI threat-feed "block" action).</summary>
    public bool BlockIP(IPAddress ip)
    {
        if (BlockConnection(0, ip, 0, "operator request"))
            return true;
        return false;
    }

    public List<NetworkConnection> GetConnections(uint pid)
    {
        return _processConnections.TryGetValue(pid, out var connections) ? new List<NetworkConnection>(connections) : new List<NetworkConnection>();
    }

    public (int TotalConnections, int Blocked, int BlockedIPs) GetStats()
    {
        int totalConnections = _processConnections.Values.Sum(conns => conns.Count);
        return (totalConnections, _connectionsBlocked, _blockedIPs.Count);
    }

    public void Dispose()
    {
        if (Interlocked.Exchange(ref _disposed, 1) == 0)
        {
            Stop();
            _monitorTimer?.Dispose();
            _monitorTask?.Wait(TimeSpan.FromSeconds(5));
        }
    }
}
