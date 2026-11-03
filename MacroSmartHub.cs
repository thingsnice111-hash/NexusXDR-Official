using System;
using System.Threading;

namespace NexusAV.Engine
{
    /// <summary>
    /// Macro-Smart Hub: routes ring-buffer telemetry (process lifecycle, image loads,
    /// hardware events) into the DCA/correlation layer and reports real DCA counters.
    /// The hardware branch feed only exists when the kernel driver is attached; without
    /// it that route is a no-op — it never fabricates telemetry.
    /// </summary>
    public class MacroSmartHub
    {
        private readonly DcaEngine _dca;
        private readonly Thread _workerThread;
        private volatile bool _running;

        public MacroSmartHub(DcaEngine dca)
        {
            _dca = dca;
            _running = true;
            _workerThread = new Thread(HubWorker) { IsBackground = true };
        }

        public void Start()
        {
            Console.WriteLine("[M.SMART] Macro-Smart Hub started.");
            _workerThread.Start();
        }

        public void Stop()
        {
            _running = false;
            _workerThread.Join(1000);
        }

        public void RouteHardwareEvent(uint pid, ulong sourceIp, ulong targetIp)
        {
            // Branch/hardware events have no user-mode producer (the driver is absent in
            // this build), so there is nothing real to verify here. Do not fabricate.
        }

        public void RouteSoftwareEvent(uint pid, uint parentPid, string eventType, string imageName)
        {
            _dca.ProcessSoftwareEvent(pid, parentPid, eventType, imageName);
        }

        private void HubWorker()
        {
            while (_running)
            {
                Thread.Sleep(60_000);
                if (!_running) break;
                int verified = Volatile.Read(ref _dca.Verifications);
                if (verified > 0)
                    Console.WriteLine($"[DCA] verifications={verified} corroborated={Volatile.Read(ref _dca.Corroborations)} vetoes={Volatile.Read(ref _dca.Vetoes)}");
            }
        }
    }
}
