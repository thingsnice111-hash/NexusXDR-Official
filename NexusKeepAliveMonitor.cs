using System.Diagnostics;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace NexusAV.Engine;

public enum KeepAliveState : byte { Unknown = 0, Healthy = 1, Suspected = 2, Frozen = 3, Terminated = 4 }

[StructLayout(LayoutKind.Sequential, Pack = 1)]
public unsafe struct KeepAlivePacket
{
    public uint Challenge;
    public uint Response;
    public uint EnginePid;
    public long TimestampUs;
    public KeepAliveState State;
    // Must stay the last field: the signed region is everything before it.
    public fixed byte Hmac[32];
}

public static unsafe class KeepAliveCrypto
{
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static bool SignPacket(ref KeepAlivePacket pkt, byte[] key)
    {
        if (key == null || key.Length != 32) return false;
        uint off = (uint)Marshal.OffsetOf(typeof(KeepAlivePacket), nameof(KeepAlivePacket.Hmac));
        fixed (byte* p = &Unsafe.As<KeepAlivePacket, byte>(ref pkt))
        {
            for (uint i = 0; i < 32; i++) p[off + i] = 0;
        }
        byte[] msg = new byte[off];
        fixed (byte* p = &Unsafe.As<KeepAlivePacket, byte>(ref pkt))
        {
            Marshal.Copy((nint)p, msg, 0, (int)off);
        }
        using var hmac = new HMACSHA256(key);
        byte[] mac = hmac.ComputeHash(msg);
        if (mac.Length != 32) return false;
        fixed (byte* p = &Unsafe.As<KeepAlivePacket, byte>(ref pkt))
        fixed (byte* macPtr = mac)
        {
            byte* dst = p + off;
            for (int i = 0; i < 32; i++) dst[i] = macPtr[i];
        }
        return true;
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static bool VerifyPacket(ref KeepAlivePacket pkt, byte[] key)
    {
        if (key == null || key.Length != 32) return false;
        KeepAlivePacket copy = pkt;
        uint off = (uint)Marshal.OffsetOf(typeof(KeepAlivePacket), nameof(KeepAlivePacket.Hmac));
        fixed (byte* p = &Unsafe.As<KeepAlivePacket, byte>(ref copy))
        {
            for (uint i = 0; i < 32; i++) p[off + i] = 0;
        }
        byte[] msg = new byte[off];
        fixed (byte* p = &Unsafe.As<KeepAlivePacket, byte>(ref copy))
        {
            Marshal.Copy((nint)p, msg, 0, (int)off);
        }
        using var hmac = new HMACSHA256(key);
        byte[] expected = hmac.ComputeHash(msg);
        if (expected.Length != 32) return false;
        fixed (byte* actual = pkt.Hmac)
        fixed (byte* expPtr = expected)
        {
            uint diff = 0;
            for (uint i = 0; i < 32; i++) diff |= (uint)(actual[i] ^ expPtr[i]);
            return diff == 0;
        }
    }

    public static byte[] DeriveKey(uint enginePid, ulong bootSeed)
    {
        byte[] material = new byte[12];
        BitConverter.TryWriteBytes(material.AsSpan(0, 4), enginePid);
        BitConverter.TryWriteBytes(material.AsSpan(4, 8), bootSeed);
        using var kdf = new HMACSHA256(new byte[] { 0x4E, 0x65, 0x78, 0x75, 0x73, 0x41, 0x56, 0x2D, 0x4B, 0x44, 0x46, 0x2D, 0x56, 0x31, 0x00, 0x01 });
        return kdf.ComputeHash(material);
    }

    // Pass/fail contract: a signed packet verifies, a tampered packet does not,
    // and a different key does not.
    public static bool SelfTest()
    {
        byte[] key = DeriveKey(4242, 0xDEADBEEFCAFEBABE);
        var pkt = new KeepAlivePacket
        {
            Challenge = 0x11223344,
            Response = 0x55667788,
            EnginePid = 4242,
            TimestampUs = 1793195804304,
            State = KeepAliveState.Healthy
        };
        if (!SignPacket(ref pkt, key)) return false;
        if (!VerifyPacket(ref pkt, key)) return false;
        pkt.Response ^= 0x1;
        if (VerifyPacket(ref pkt, key)) return false;
        pkt.Response ^= 0x1;
        if (!VerifyPacket(ref pkt, key)) return false;
        byte[] wrongKey = DeriveKey(4242, 0xDEADBEEFCAFEBABE ^ 1);
        return !VerifyPacket(ref pkt, wrongKey);
    }
}

public sealed unsafe class NexusKeepAliveMonitor : IDisposable
{
    private readonly byte[] _key;
    private readonly int _intervalMs = 10;
    private readonly int _threshold = 3;
    private readonly uint _enginePid;
    private Thread? _thread;
    private int _disposed;
    private int _successiveFailures;
    private KeepAliveState _lastState = KeepAliveState.Healthy;
    private KeepAlivePacket _lastPacket;
    private readonly Action<KeepAliveState, uint, uint, long> _onFrozen;

    public KeepAliveState LastState
    {
        get
        {
            byte raw = Volatile.Read(ref Unsafe.As<KeepAliveState, byte>(ref _lastState));
            return (KeepAliveState)raw;
        }
    }

    public NexusKeepAliveMonitor(uint enginePid, ulong bootSeed, int intervalMs = 10, int failureThreshold = 3, Action<KeepAliveState, uint, uint, long>? onFrozen = null)
    {
        _enginePid = enginePid;
        _intervalMs = intervalMs;
        _threshold = failureThreshold;
        _key = KeepAliveCrypto.DeriveKey(enginePid, bootSeed);
        _onFrozen = onFrozen ?? ((s, p, c, t) => { });
    }

    public void Start()
    {
        ObjectDisposedException.ThrowIf(_disposed == 1, this);
        if (_thread != null) return;
        _thread = new Thread(Loop) { Name = "Nexus-KA-Mon", Priority = ThreadPriority.Normal, IsBackground = true };
        _thread.Start();
    }

    public bool TryRespondToChallenge(uint expectedChallenge, uint response, out KeepAlivePacket pkt)
    {
        pkt = default;
        pkt.Challenge = expectedChallenge;
        pkt.Response = response;
        pkt.EnginePid = _enginePid;
        pkt.TimestampUs = Stopwatch.GetTimestamp();
        pkt.State = KeepAliveState.Healthy;
        if (!KeepAliveCrypto.SignPacket(ref pkt, _key)) return false;
        _lastPacket = pkt;
        return true;
    }

    private void Loop()
    {
        while (Volatile.Read(ref EngineState.ShuttingDown) == 0 && Volatile.Read(ref _disposed) == 0)
        {
            KeepAlivePacket snap = _lastPacket;
            bool valid = false;
            bool fresh = false;
            if (KeepAliveCrypto.VerifyPacket(ref snap, _key) && snap.Response != 0)
            {
                valid = true;
                long ageUs = (Stopwatch.GetTimestamp() - snap.TimestampUs) * 1_000_000L / Stopwatch.Frequency;
                // Inverted heartbeat: freshness is driven by driver ETYPE_KA_CHALLENGE replies, not a self-probe.
                fresh = ageUs >= -100_000 && ageUs <= Math.Max(500_000L, 50L * _intervalMs * 1_000L);
            }

            if (!valid)
            {
                // No driver challenge answered yet — stay Unknown, do not invent a challenge.
                Volatile.Write(ref Unsafe.As<KeepAliveState, byte>(ref _lastState), (byte)KeepAliveState.Unknown);
                Thread.Sleep(_intervalMs);
                continue;
            }

            if (valid && fresh)
            {
                Volatile.Write(ref _successiveFailures, 0);
                Volatile.Write(ref Unsafe.As<KeepAliveState, byte>(ref _lastState), (byte)KeepAliveState.Healthy);
            }
            else
            {
                int cur = Interlocked.Increment(ref _successiveFailures);
                if (cur == _threshold)
                {
                    Volatile.Write(ref Unsafe.As<KeepAliveState, byte>(ref _lastState), (byte)KeepAliveState.Suspected);
                }
                else if (cur >= _threshold * 2)
                {
                    Volatile.Write(ref Unsafe.As<KeepAliveState, byte>(ref _lastState), (byte)KeepAliveState.Frozen);
                    try { _onFrozen(KeepAliveState.Frozen, _enginePid, snap.Challenge, snap.TimestampUs); } catch { }
                }
            }
            Thread.Sleep(_intervalMs);
        }
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static uint RotateChallenge(uint c) => unchecked(((c << 7) | (c >> (32 - 7))) ^ 0x9E3779B9u);

    public void Dispose()
    {
        if (Interlocked.CompareExchange(ref _disposed, 1, 0) != 0) return;
        Volatile.Write(ref EngineState.ShuttingDown, 1);
        _thread?.Join(Math.Min(_intervalMs * 20, 500));
    }
}
