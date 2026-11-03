using System;
using System.Collections.Generic;
using System.Runtime.CompilerServices;
using System.Runtime.Intrinsics;
using System.Runtime.Intrinsics.X86;
using System.Threading;

namespace NexusAV.Engine;

public unsafe class FactChecker : IDisposable
{
    private int _anomalyCount;
    private readonly Action<uint, ulong>? _anomalyHandler;
    public readonly bool Avx2Supported;

    // Populated from the ring-buffer image-load consumer thread and read from the LBR
    // analysis thread. Guarded by _rangesLock; the HashSet gives O(1) positive hits on
    // validated module base pages, the range list covers interiors.
    private readonly object _rangesLock = new();
    private readonly List<(ulong Min, ulong Max)> _validRanges = new();
    private readonly HashSet<ulong> _validStartPages = new();

    public int AnomalyCount => Volatile.Read(ref _anomalyCount);

    public FactChecker()
    {
        Avx2Supported = Avx2.IsSupported;
    }

    public FactChecker(Action<uint, ulong> anomalyHandler) : this()
    {
        _anomalyHandler = anomalyHandler;
    }

    public void Reset() => Volatile.Write(ref _anomalyCount, 0);

    public void AddValidModuleRange(ulong baseVA, ulong size)
    {
        if (size == 0) return;
        lock (_rangesLock)
        {
            _validRanges.Add((baseVA, baseVA + size - 1));
            _validStartPages.Add(baseVA >> 12);
        }
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private bool IsInAnyRange(ulong addr, ulong validMin, ulong validMax)
    {
        if (addr >= validMin && addr <= validMax)
            return true;

        lock (_rangesLock)
        {
            // O(1) accelerator for validated module bases.
            if (_validStartPages.Contains(addr >> 12))
                return true;

            for (int i = 0; i < _validRanges.Count; i++)
            {
                var r = _validRanges[i];
                if (addr >= r.Min && addr <= r.Max)
                    return true;
            }
        }
        return false;
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public void AnalyzeBranchTargets(uint processId, ReadOnlySpan<ulong> targetAddresses, ulong validMin, ulong validMax)
    {
        fixed (ulong* p = targetAddresses)
        {
            int i = 0;
            int len = targetAddresses.Length;

            Vector256<ulong> minV = Vector256.Create(validMin);
            Vector256<ulong> maxV = Vector256.Create(validMax);

            bool noExtraRanges;
            lock (_rangesLock) noExtraRanges = _validRanges.Count == 0;
            bool useAvx = Avx2Supported && len >= 4 && noExtraRanges;

            for (; useAvx && i <= len - 4; i += 4)
            {
                Vector256<ulong> t = Avx.LoadVector256(p + i);
                Vector256<ulong> outsideMask = Vector256.GreaterThan(minV, t) | Vector256.GreaterThan(t, maxV);

                if (outsideMask != Vector256<ulong>.Zero)
                {
                    for (int j = 0; j < 4; j++)
                    {
                        if (outsideMask.GetElement(j) != 0)
                            HandleAnomaly(processId, p[i + j]);
                    }
                }
            }

            for (; i < len; i++)
            {
                ulong addr = p[i];
                if (!IsInAnyRange(addr, validMin, validMax))
                    HandleAnomaly(processId, addr);
            }
        }
    }

    [MethodImpl(MethodImplOptions.NoInlining)]
    private void HandleAnomaly(uint processId, ulong suspectAddress)
    {
        Interlocked.Increment(ref _anomalyCount);
        _anomalyHandler?.Invoke(processId, suspectAddress);
    }

    public void Dispose()
    {
    }
}
