using System;
using System.Collections.Generic;
using System.Threading;

namespace NexusAV.Engine;

public enum EdgeType { Tree, ThreadInject, PpidSpoof, RwxInject, DnsQuery, ShieldAction }

public readonly record struct CrossEdge(uint SrcPid, uint DstPid, EdgeType Type, int Weight, DateTimeOffset Timestamp, string Extra = "");

/// <summary>
/// Bounded, self-pruning cross-process relationship graph. Storyteller detectors push
/// edges (tree ancestry, injection, spoofing, DNS) and <see cref="EngineFeedRunner.EventPump"/>
/// drains them to the GUI. Retention is capped (oldest edges are dropped and the
/// snapshot cursor is rebased) and dead ends are pruned so a long session cannot
/// grow memory without bound.
/// </summary>
public sealed class CrossProcessGraph
{
    private const int MaxRetainedEdges = 8192;
    private const int MaxEdgesPerPid = 256;
    private const int MaxAncestryDepth = 16;

    private readonly Dictionary<uint, List<CrossEdge>> _adj = new();
    private readonly Dictionary<uint, uint> _parentOf = new();
    private readonly List<CrossEdge> _all = new();
    private readonly object _lock = new();

    // Number of edges dropped from the front of _all; the absolute cursor is
    // _baseIndex + _all.Count so SnapshotSince stays correct across retention trims.
    private int _baseIndex;
    private int _edgeCount;

    public int EdgeCount => _edgeCount;

    public int TotalEdges { get { lock (_lock) return _baseIndex + _all.Count; } }

    public void AddEdge(CrossEdge e)
    {
        lock (_lock)
        {
            if (!_adj.TryGetValue(e.SrcPid, out var lst))
            {
                lst = new List<CrossEdge>(4);
                _adj[e.SrcPid] = lst;
            }
            lst.Add(e);
            if (lst.Count > MaxEdgesPerPid)
                lst.RemoveRange(0, lst.Count - MaxEdgesPerPid);

            if (e.Type == EdgeType.Tree && e.DstPid != 0 && e.DstPid != uint.MaxValue && !_parentOf.ContainsKey(e.DstPid))
                _parentOf[e.DstPid] = e.SrcPid;

            _all.Add(e);
            if (_all.Count > MaxRetainedEdges)
            {
                int drop = _all.Count - MaxRetainedEdges;
                _all.RemoveRange(0, drop);
                _baseIndex += drop;
            }
        }
        Interlocked.Increment(ref _edgeCount);
    }

    /// <summary>True once a process-start edge was recorded for this child.</summary>
    public bool HasTreeEdge(uint childPid)
    {
        lock (_lock) return _parentOf.ContainsKey(childPid);
    }

    /// <summary>Return edges appended after <paramref name="cursor"/> and the new absolute cursor.</summary>
    public List<CrossEdge> SnapshotSince(ref int cursor)
    {
        var result = new List<CrossEdge>();
        lock (_lock)
        {
            int start = Math.Max(cursor, _baseIndex);
            int end = _baseIndex + _all.Count;
            for (int i = start; i < end; i++)
                result.Add(_all[i - _baseIndex]);
            cursor = end;
        }
        return result;
    }

    public List<CrossEdge> Edges
    {
        get { lock (_lock) return new List<CrossEdge>(_all); }
    }

    public List<CrossEdge> GetEdges(uint pid)
    {
        lock (_lock)
            return _adj.TryGetValue(pid, out var l) ? new List<CrossEdge>(l) : new List<CrossEdge>(0);
    }

    public List<uint> SnapshotSrcPids()
    {
        lock (_lock) return new List<uint>(_adj.Keys);
    }

    /// <summary>Parent chain of <paramref name="pid"/> (direct parent first), bounded and cycle-safe.</summary>
    public List<uint> GetAncestry(uint pid)
    {
        var chain = new List<uint>(4);
        lock (_lock)
        {
            var visited = new HashSet<uint> { pid };
            uint cur = pid;
            for (int i = 0; i < MaxAncestryDepth; i++)
            {
                if (!_parentOf.TryGetValue(cur, out uint parent)) break;
                if (parent == 0 || parent == uint.MaxValue || !visited.Add(parent)) break;
                chain.Add(parent);
                cur = parent;
            }
        }
        return chain;
    }

    public IEnumerable<uint> GetDescendants(uint pid)
    {
        var visited = new HashSet<uint>();
        var stack = new Stack<uint>();
        stack.Push(pid);
        lock (_lock)
        {
            while (stack.Count > 0)
            {
                var cur = stack.Pop();
                if (!visited.Add(cur)) continue;
                if (_adj.TryGetValue(cur, out var edges))
                    foreach (var e in edges)
                        if (e.Type is EdgeType.Tree or EdgeType.ThreadInject or EdgeType.RwxInject or EdgeType.PpidSpoof)
                            stack.Push(e.DstPid);
            }
        }
        visited.Remove(pid);
        return visited;
    }

    /// <summary>
    /// Drop adjacency for source PIDs whose edges all point at dead processes too.
    /// <paramref name="isAlive"/> is fed from the shared ProcessSnapshotCache so this
    /// never takes its own process snapshot. Returns how many source entries were removed.
    /// </summary>
    public int Prune(Func<uint, bool> isAlive)
    {
        int removed = 0;
        lock (_lock)
        {
            List<uint>? dead = null;
            foreach (var kv in _adj)
            {
                if (isAlive(kv.Key)) continue;
                bool anyLive = false;
                foreach (var e in kv.Value)
                {
                    if (e.DstPid == 0 || e.DstPid == uint.MaxValue || isAlive(e.DstPid))
                    {
                        anyLive = true;
                        break;
                    }
                }
                if (!anyLive) (dead ??= new List<uint>()).Add(kv.Key);
            }
            if (dead != null)
            {
                foreach (var k in dead)
                {
                    _adj.Remove(k);
                    removed++;
                }
            }

            if (_parentOf.Count > MaxRetainedEdges * 2)
            {
                _parentOf.Clear();
                for (int i = 0; i < _all.Count; i++)
                {
                    var e = _all[i];
                    if (e.Type == EdgeType.Tree && e.DstPid != 0 && e.DstPid != uint.MaxValue && !_parentOf.ContainsKey(e.DstPid))
                        _parentOf[e.DstPid] = e.SrcPid;
                }
            }
        }
        return removed;
    }
}
