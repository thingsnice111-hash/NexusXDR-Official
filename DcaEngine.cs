using System;
using System.Text;
using System.Threading;

namespace NexusAV.Engine
{
    /// <summary>
    /// Cross-verification gate ("DCA"): before the engine acts on a behavioral
    /// (counter A) score from the Storyteller, this checks independent identity
    /// evidence (counter B: Authenticode state, VirusTotal hash verdict, hidden-PID
    /// discrepancy) and the graph ancestry chain. Single-source activation with hard
    /// counter-evidence (a validly signed image and no corroboration) is held for
    /// review instead of acted on. All user-mode, read-only.
    /// </summary>
    public sealed class DcaEngine
    {
        private readonly Storyteller _storyteller;

        /// <summary>Optional VirusTotal scanner; its 24h hash cache is the cloud-reputation source.</summary>
        public VirusTotalScanner? Vt { get; set; }

        /// <summary>Known-bad fingerprint store; an exact identity hit is the strongest corroboration.</summary>
        public FingerprintStore? Fingerprints { get; set; }

        public int Verifications;
        public int Vetoes;
        public int Corroborations;

        public DcaEngine(Storyteller storyteller)
        {
            _storyteller = storyteller;
        }

        public readonly record struct DcaVerdict(bool Proceed, bool Corroborated, string Reason);

        /// <summary>
        /// Verify a node that reached the "act" threshold against independent sources.
        /// Proceed=false only when a trusted signature contradicts the behavioral score
        /// and nothing else corroborates it; otherwise the action proceeds.
        /// </summary>
        public DcaVerdict VerifyBeforeAct(uint pid)
        {
            Interlocked.Increment(ref Verifications);
            var node = _storyteller.GetOrAdd(pid, 0, "unknown.exe");

            bool signedTrusted = node.SigState is SignatureState.MicrosoftSigned or SignatureState.TrustedPublisher;
            bool badSig = node.SigState is SignatureState.Invalid or SignatureState.Untrusted;

            int vtMaliciousCount = 0, vtTotal = 0;
            bool haveVt = node.ImageSha256 != null && Vt != null &&
                          Vt.TryGetCachedVerdict(node.ImageSha256, out vtMaliciousCount, out vtTotal);
            // One or two engines flagging a file is noise far more often than malware, so a weak
            // cloud verdict no longer corroborates a behavioral score on its own.
            bool vtStrong = haveVt && vtMaliciousCount >= RealtimeScanner.ProbableEngineThreshold;
            bool vtWeak = haveVt && vtMaliciousCount > 0 && !vtStrong;

            string knownBadKind = "";
            if (Fingerprints != null && node.ImageSha256 != null && node.ImageSha256.Length > 0)
            {
                var hit = Fingerprints.Lookup(Convert.ToHexString(node.ImageSha256).ToLowerInvariant(), "", "", "");
                if (hit is { } m) knownBadKind = m.Kind;
            }

            bool hidden = HiddenProcessScanner.IsReportedHidden(pid);

            var sb = new StringBuilder(160);
            bool corroborated = false;
            if (knownBadKind.Length > 0) { corroborated = true; sb.Append("known-bad fingerprint (").Append(knownBadKind).Append("); "); }
            if (badSig) { corroborated = true; sb.Append("invalid signature; "); }
            if (vtStrong) { corroborated = true; sb.Append("VT ").Append(vtMaliciousCount).Append('/').Append(vtTotal).Append("; "); }
            if (hidden) { corroborated = true; sb.Append("hidden PID; "); }
            if (vtWeak && !corroborated)
                sb.Append("weak VT ").Append(vtMaliciousCount).Append('/').Append(vtTotal).Append(" (not corroborating alone); ");

            string chain = _storyteller.DescribeAncestry(pid);
            if (chain.Length > 0) sb.Append("chain ").Append(chain).Append("; ");

            bool contradicted = signedTrusted && !corroborated;
            bool proceed = !contradicted;
            string reason = sb.Length == 0
                ? "single-source signal, no independent contradiction"
                : sb.ToString().TrimEnd(' ', ';');

            if (!proceed) Interlocked.Increment(ref Vetoes);
            else if (corroborated) Interlocked.Increment(ref Corroborations);

            Console.WriteLine($"[DCA] pid={pid} {(proceed ? (corroborated ? "corroborated" : "proceed") : "VETO")} conf={node.Confidence} :: {reason}");
            if (!proceed)
                EventBus.Detection("dca", "medium", "Action held by cross-verification",
                    $"pid={pid} {node.ImageName} — {reason}", pid);

            return new DcaVerdict(proceed, corroborated, reason);
        }

        /// <summary>Process lifecycle notification from the ring-buffer consumer (kernel-driver feed).</summary>
        public void ProcessSoftwareEvent(uint pid, uint parentPid, string eventType, string imageName)
        {
            if (string.Equals(eventType, "PROCESS_CREATE", StringComparison.Ordinal))
                _storyteller.ReportProcessStart(pid, parentPid, imageName);
        }
    }
}
