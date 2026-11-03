using System;
using System.IO;
using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using System.Threading;

namespace NexusAV.Engine;

/// <summary>
/// Named-pipe server that accepts the Mystral companion's telemetry feed.
/// Mystral publishes <c>NEXUS_EVENT</c> lines (findings + process starts) into this
/// pipe; the engine republishes them as source-tagged events and may corroborate
/// high-severity findings through the Storyteller/DCA rails.
///
/// Direction rules that keep the boundary safe:
///  - The engine is the only actor. Mystral never executes engine commands.
///  - The engine may send exactly one fixed, read-only request down the pipe:
///    <c>{"c":"scan"}</c> (triggers an immediate memory pass on the sensor side).
///    Anything else Mystral ignores by design, so a compromised engine can never
///    arm the sensor's responder or inject anything into it.
///  - Inbound is verified too: the pipe DACL admits only this user, SYSTEM and Administrators,
///    and every accepted connection is checked against the connecting process image, so a random
///    local process cannot invent sensor evidence.
/// </summary>
public sealed class MystralBridgeServer : IDisposable
{
    public const string PipeName = "NexusMystralBridge";

    /// <summary>The only image allowed to feed this pipe.</summary>
    private const string SensorImageName = "Mystral.exe";

    private readonly Action<uint, string, string, string, string> _onFinding;
    private readonly Action<uint, uint, string, string, bool> _onProc;
    private readonly Action<bool> _onConnection;
    private Thread? _thread;
    private NamedPipeServerStream? _pipe;
    private volatile bool _running;
    private volatile bool _clientConnected;
    private int _disposed;

    public bool ClientConnected => _clientConnected;
    public event Action<string>? OnLog;

    public MystralBridgeServer(
        Action<uint, string, string, string, string> onFinding,
        Action<uint, uint, string, string, bool> onProc,
        Action<bool> onConnection)
    {
        _onFinding = onFinding;
        _onProc = onProc;
        _onConnection = onConnection;
    }

    public void Start()
    {
        _running = true;
        _thread = new Thread(Loop) { IsBackground = true, Name = "Nexus-MystralBridge" };
        _thread.Start();
    }

    /// <summary>Asks the connected sensor for one immediate memory pass. Returns false when no sensor is attached.</summary>
    public bool RequestScan()
    {
        var p = _pipe;
        if (p == null || !p.IsConnected) return false;
        try
        {
            byte[] bytes = Encoding.UTF8.GetBytes("{\"c\":\"scan\"}\n");
            p.Write(bytes, 0, bytes.Length);
            return true;
        }
        catch
        {
            return false;
        }
    }

    private void Loop()
    {
        while (_running)
        {
            bool accepted = false;
            try
            {
                using var server = NamedPipeServerStreamAcl.Create(
                    PipeName, PipeDirection.InOut, 1, PipeTransmissionMode.Byte, PipeOptions.Asynchronous,
                    4096, 4096, BuildPipeSecurity());
                _pipe = server;
                server.WaitForConnection();
                if (!IsAllowedPeer(server, out string peer))
                {
                    OnLog?.Invoke($"bridge peer rejected: {peer} — only {SensorImageName} may feed this pipe");
                    EventBus.Status($"mystral_peer_rejected peer={SafeToken(peer)}");
                    try { server.Disconnect(); } catch { }
                    continue;
                }
                accepted = true;
                _clientConnected = true;
                _onConnection(true);
                OnLog?.Invoke($"Mystral sensor connected ({peer})");
                using var reader = new StreamReader(server, new UTF8Encoding(false));
                while (_running && server.IsConnected)
                {
                    string? line;
                    try { line = reader.ReadLine(); }
                    catch (IOException) { break; }
                    if (line == null) break; // client closed the pipe
                    HandleLine(line);
                }
            }
            catch (Exception ex) when (_running)
            {
                OnLog?.Invoke("bridge accept fault: " + ex.Message);
            }
            finally
            {
                _pipe = null;
                if (_clientConnected)
                {
                    _clientConnected = false;
                    _onConnection(false);
                }
                if (accepted) OnLog?.Invoke("Mystral sensor disconnected");
            }
            Thread.Sleep(300);
        }
    }

    /// <summary>
    /// Default pipe security would let every local process open this pipe and publish fake sensor
    /// findings, which the engine then treats as evidence. Admit only the account running the
    /// engine plus SYSTEM and Administrators.
    /// </summary>
    private static PipeSecurity BuildPipeSecurity()
    {
        var acl = new PipeSecurity();
        using WindowsIdentity self = WindowsIdentity.GetCurrent();
        FullControl(acl, self.User!);
        FullControl(acl, new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null));
        FullControl(acl, new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null));
        return acl;
    }

    private static void FullControl(PipeSecurity acl, IdentityReference who)
        => acl.AddAccessRule(new PipeAccessRule(who, PipeAccessRights.FullControl, AccessControlType.Allow));

    /// <summary>
    /// Identifies the process on the other end of the pipe. Anything we cannot name, and anything
    /// that is not the sensor image, is refused — an unnamed peer is exactly how fabricated
    /// findings would get in.
    /// </summary>
    private static bool IsAllowedPeer(NamedPipeServerStream server, out string peer)
    {
        peer = "unknown";
        try
        {
            if (!GetNamedPipeClientProcessId(server.SafePipeHandle.DangerousGetHandle(), out uint pid) || pid == 0)
                return false;

            string path = SafeProcessKiller.ImagePathOf(pid);
            if (path.Length == 0)
            {
                peer = $"pid={pid} image-unreadable";
                return false;
            }
            peer = $"pid={pid} img={path}";
            return string.Equals(Path.GetFileName(path), SensorImageName, StringComparison.OrdinalIgnoreCase);
        }
        catch
        {
            return false;
        }
    }

    private static string SafeToken(string s) => s.Replace('\\', '/').Replace(' ', '_');

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool GetNamedPipeClientProcessId(IntPtr pipe, out uint clientProcessId);

    private void HandleLine(string line)
    {
        int idx = line.IndexOf(EventBus.EventPrefix, StringComparison.Ordinal);
        if (idx < 0) return;
        string json = line.Substring(idx + EventBus.EventPrefix.Length).Trim();
        try
        {
            using var doc = JsonDocument.Parse(json);
            var r = doc.RootElement;
            if (!r.TryGetProperty("t", out var te)) return;
            switch (te.GetString())
            {
                case "mystral_finding":
                    _onFinding(
                        r.TryGetProperty("pid", out var fp) && fp.TryGetUInt32(out uint fpid) ? fpid : 0,
                        r.TryGetProperty("img", out var fi) ? fi.GetString() ?? "" : "",
                        r.TryGetProperty("kind", out var fk) ? fk.GetString() ?? "" : "",
                        r.TryGetProperty("sev", out var fs) ? fs.GetString() ?? "" : "",
                        r.TryGetProperty("detail", out var fd) ? fd.GetString() ?? "" : "");
                    break;
                case "mystral_proc":
                    _onProc(
                        r.TryGetProperty("pid", out var pp) && pp.TryGetUInt32(out uint ppid0) ? ppid0 : 0,
                        r.TryGetProperty("ppid", out var ppp) && ppp.TryGetUInt32(out uint pppid) ? pppid : 0,
                        r.TryGetProperty("img", out var pi) ? pi.GetString() ?? "" : "",
                        r.TryGetProperty("cmd", out var pc) ? pc.GetString() ?? "" : "",
                        r.TryGetProperty("ondisk", out var po) && po.ValueKind == JsonValueKind.True);
                    break;
                default:
                    OnLog?.Invoke($"ignored unknown mystral event t={te.GetString()}");
                    break;
            }
        }
        catch (Exception ex)
        {
            OnLog?.Invoke("bad mystral line: " + ex.Message);
        }
    }

    public void Dispose()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0) return;
        _running = false;
        try { _pipe?.Dispose(); } catch { }
    }
}
