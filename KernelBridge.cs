using System.IO.MemoryMappedFiles;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace NexusAV.Engine;

public static unsafe partial class KernelBridge
{
    public const string DevicePath = @"\\.\NexusAV";
    public const uint FILE_DEVICE_NEXUSAV = 0x000022;
    public const uint METHOD_BUFFERED = 0;
    public const uint FILE_ANY_ACCESS = 0;

    public static readonly uint IOCTL_NEXUS_BASE        = MakeIOCTL(FILE_DEVICE_NEXUSAV, 0x000, METHOD_BUFFERED, FILE_ANY_ACCESS);
    public static readonly uint IOCTL_NEXUS_PROTECT_PID = MakeIOCTL(FILE_DEVICE_NEXUSAV, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS);
    public static readonly uint IOCTL_NEXUS_HEARTBEAT   = MakeIOCTL(FILE_DEVICE_NEXUSAV, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS);
    public static readonly uint IOCTL_NEXUS_MAP_SECTION = MakeIOCTL(FILE_DEVICE_NEXUSAV, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS);
    public static readonly uint IOCTL_NEXUS_BYPASS      = MakeIOCTL(FILE_DEVICE_NEXUSAV, 0x803, METHOD_BUFFERED, FILE_ANY_ACCESS);
    public static readonly uint IOCTL_NEXUS_KA_RESPONSE = MakeIOCTL(FILE_DEVICE_NEXUSAV, 0x804, METHOD_BUFFERED, FILE_ANY_ACCESS);
    public static readonly uint IOCTL_NEXUS_PREBOOT_QUERY = MakeIOCTL(FILE_DEVICE_NEXUSAV, 0x805, METHOD_BUFFERED, FILE_ANY_ACCESS);
    public static readonly uint IOCTL_NEXUS_WFP_BLOCK   = MakeIOCTL(FILE_DEVICE_NEXUSAV, 0x806, METHOD_BUFFERED, FILE_ANY_ACCESS);
    public static readonly uint IOCTL_NEXUS_BOOT_SEED_EXCHANGE = MakeIOCTL(FILE_DEVICE_NEXUSAV, 0x807, METHOD_BUFFERED, FILE_ANY_ACCESS);
    public static readonly uint IOCTL_NEXUS_RAW_DISK_READ = MakeIOCTL(FILE_DEVICE_NEXUSAV, 0x808, METHOD_BUFFERED, FILE_ANY_ACCESS);

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct RawDiskReadRequest
    {
        public uint DiskNumber;
        public ulong SectorOffset;
        public uint SectorCount;
    }

    // User-mode raw disk replies are not marshalled to the kernel; Data is a
    // managed buffer so callers can copy/hash it without fixed-pointer gymnastics.
    public struct RawDiskReadReply
    {
        public uint BytesRead;
        public uint Status;
        public byte[] Data;

        public const int DataSize = 512;

        public RawDiskReadReply()
        {
            BytesRead = 0;
            Status = 0;
            Data = new byte[DataSize];
        }
    }

    [LibraryImport("kernel32.dll", EntryPoint = "CreateFileW", SetLastError = true, StringMarshalling = StringMarshalling.Utf16)]
    private static partial SafeFileHandle CreateFileNative(
        string lpFileName,
        uint dwDesiredAccess,
        uint dwShareMode,
        IntPtr lpSecurityAttributes,
        uint dwCreationDisposition,
        uint dwFlagsAndAttributes,
        IntPtr hTemplateFile);

    public const uint GENERIC_READ = 0x80000000;
    public const uint GENERIC_WRITE = 0x40000000;
    public const uint OPEN_EXISTING = 3;

    public static SafeFileHandle OpenDriver()
    {
        return CreateFileNative(
            DevicePath,
            GENERIC_READ | GENERIC_WRITE,
            0,
            IntPtr.Zero,
            OPEN_EXISTING,
            0,
            IntPtr.Zero);
    }

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static partial bool DeviceIoControl(
        SafeFileHandle hDevice,
        uint dwIoControlCode,
        ref uint lpInBuffer,
        uint nInBufferSize,
        void* lpOutBuffer,
        uint nOutBufferSize,
        out uint lpBytesReturned,
        IntPtr lpOverlapped);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static partial bool DeviceIoControlSimple(
        SafeFileHandle hDevice,
        uint dwIoControlCode,
        IntPtr lpInBuffer,
        uint nInBufferSize,
        IntPtr lpOutBuffer,
        uint nOutBufferSize,
        out uint lpBytesReturned,
        IntPtr lpOverlapped);

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static uint MakeIOCTL(uint deviceType, uint function, uint method, uint access)
    {
        return (deviceType << 16) | (access << 14) | (function << 2) | method;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct LbrTelemetryEvent
    {
        public uint  EventType;
        public uint  ProcessId;
        public uint  ThreadId;
        public ulong SourceIp;
        public ulong TargetIp;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct ProcessTelemetryEvent
    {
        public uint EventType;
        public uint ProcessId;
        public uint ParentPid;
        public byte Create;
        public byte ExitStatusHigh;
        public uint ExitStatusLow;
        public fixed byte ImageName[16];
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct ImageLoadTelemetryEvent
    {
        public uint EventType;
        public uint ProcessId;
        public ulong ImageBase;
        public ulong ImageSize;
        public fixed byte ModuleName[32];
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct ThreadTelemetryEvent
    {
        public uint EventType;
        public uint ProcessId;
        public uint CreatingPid;
        public uint ThreadId;
        public ulong StartIp;
        public byte IsRemote;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct NetworkTelemetryEvent
    {
        public uint EventType;
        public uint ProcessId;
        public uint RemoteIp;
        public ushort RemotePort;
        public byte IsBlocked;
        public byte Protocol;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct EtwTiTelemetryEvent
    {
        public uint   EventType;
        public uint   CallerPid;
        public uint   TargetPid;
        public ulong  AllocationBase;
        public uint   AllocationType;
        public uint   Protect;
        public ulong  Size;
    }

    public const uint PAGE_EXECUTE_READWRITE = 0x40;
    public const uint PAGE_EXECUTE_WRITECOPY = 0x80;
    public const uint PAGE_EXECUTE = 0x10;
    public const uint PAGE_EXECUTE_READ = 0x20;

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct PrebootFileResult
    {
        public fixed byte FileName[32];
        public fixed byte Sha256[32];
        public uint StatusFlags;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct PrebootScanResult
    {
        public uint EventType;
        public uint ScanPass;
        public uint TamperCount;
        public uint FileCount;
        public ulong IdtBase;
        public uint IdtLimit;
        public ulong GdtBase;
        public uint GdtLimit;
        public ulong Cr0;
        public ulong Cr3;
        public ulong Cr4;
        public ulong MsrGsBase;
        public ulong BootTick;
        public PrebootFileResult File0;
        public PrebootFileResult File1;
        public PrebootFileResult File2;
        public PrebootFileResult File3;
        public PrebootFileResult File4;
        public PrebootFileResult File5;
        public PrebootFileResult File6;
        public PrebootFileResult File7;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct KaChallengeEvent
    {
        public uint EventType;
        public uint Challenge;
        public uint EnginePid;
        public uint Pad0;
        public long TimestampUs;
        public fixed byte Hmac[32];
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct PrebootSummaryEvent
    {
        public uint EventType;
        public uint ScanPass;
        public uint TamperCount;
        public uint FileCount;
        public ulong IdtBase;
        public ulong GdtBase;
        public ulong Cr0;
        public ulong Cr3;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct NexusBootSeedReply
    {
        public fixed byte RootKey[32];
        public ulong BootSeed;
        public uint StatusFlags;
    }

    public const uint RINGBUFFER_SLOT_SIZE = 64;

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct RingBufferHeader
    {
        public uint Head;
        public uint Tail;
        public uint Size;
        public uint EventCount;
        public fixed uint PidConfidence[8];
        public fixed uint Reserved[4];
    }

    public static void MapSection(SafeFileHandle driverHandle)
    {
        if (driverHandle == null || driverHandle.IsInvalid || driverHandle.IsClosed)
        {
            Console.WriteLine("[WARN] MapSection: driver handle invalid, skipping IOCTL_NEXUS_MAP_SECTION");
            return;
        }
        try
        {
            bool ok = DeviceIoControlSimple(
                driverHandle,
                IOCTL_NEXUS_MAP_SECTION,
                IntPtr.Zero, 0,
                IntPtr.Zero, 0,
                out _,
                IntPtr.Zero);
            if (!ok)
            {
                int err = Marshal.GetLastPInvokeError();
                Console.WriteLine($"[WARN] MapSection: IOCTL_NEXUS_MAP_SECTION failed (win32={err}), will fallback to CreateNew");
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[WARN] MapSection: IOCTL_NEXUS_MAP_SECTION exception: {ex.Message}, fallback to CreateNew");
        }
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static void ProcessRingBuffer(
        IntPtr baseAddress,
        nuint regionSize,
        Action<LbrTelemetryEvent>? lbrConsumer = null,
        Action<EtwTiTelemetryEvent>? etwConsumer = null,
        Action<ProcessTelemetryEvent, uint>? processConsumer = null,
        Action<ImageLoadTelemetryEvent>? imageConsumer = null,
        Action<ThreadTelemetryEvent>? threadConsumer = null,
        Action<NetworkTelemetryEvent>? networkConsumer = null,
        Action<PrebootSummaryEvent>? prebootConsumer = null,
        Action<KaChallengeEvent>? kaChallengeConsumer = null)
    {
        if (baseAddress == IntPtr.Zero || regionSize < (nuint)Unsafe.SizeOf<RingBufferHeader>()) return;

        ref RingBufferHeader hdr = ref Unsafe.AsRef<RingBufferHeader>((void*)baseAddress);
        if (hdr.Size == 0) return;

        uint size = hdr.Size;
        uint tail = Volatile.Read(ref hdr.Tail);
        uint head = Volatile.Read(ref hdr.Head);
        if (head == tail) return;

        uint headerSize = (uint)Unsafe.SizeOf<RingBufferHeader>();

        while (tail != head)
        {
            byte* slotBase = (byte*)baseAddress + headerSize + (nuint)(tail % size) * RINGBUFFER_SLOT_SIZE;
            uint eventType = *(uint*)slotBase;

            switch (eventType)
            {
                case 0:
                    lbrConsumer?.Invoke(Unsafe.AsRef<LbrTelemetryEvent>(slotBase));
                    break;
                case 1:
                case 2:
                    processConsumer?.Invoke(Unsafe.AsRef<ProcessTelemetryEvent>(slotBase), eventType);
                    break;
                case 3:
                    imageConsumer?.Invoke(Unsafe.AsRef<ImageLoadTelemetryEvent>(slotBase));
                    break;
                case 4:
                    threadConsumer?.Invoke(Unsafe.AsRef<ThreadTelemetryEvent>(slotBase));
                    break;
                case 5:
                    networkConsumer?.Invoke(Unsafe.AsRef<NetworkTelemetryEvent>(slotBase));
                    break;
                case 6:
                    prebootConsumer?.Invoke(Unsafe.AsRef<PrebootSummaryEvent>(slotBase));
                    break;
                case 7:
                    kaChallengeConsumer?.Invoke(Unsafe.AsRef<KaChallengeEvent>(slotBase));
                    break;
                case 8:
                    etwConsumer?.Invoke(Unsafe.AsRef<EtwTiTelemetryEvent>(slotBase));
                    break;
            }
            tail = (tail + 1); // driver Head/Tail are monotonic counters; slot uses % size
            Volatile.Write(ref hdr.Tail, tail);
        }
    }

    public static uint GetLbrEventSize() => (uint)Unsafe.SizeOf<LbrTelemetryEvent>();
    public static uint GetHeaderSize() => (uint)Unsafe.SizeOf<RingBufferHeader>();

    public static unsafe bool QueryPrebootResults(SafeFileHandle driverHandle, out PrebootScanResult result)
    {
        result = default;
        if (driverHandle == null || driverHandle.IsInvalid || driverHandle.IsClosed) return false;
        try
        {
            int size = Unsafe.SizeOf<PrebootScanResult>();
            IntPtr buf = Marshal.AllocHGlobal(size);
            try
            {
                Unsafe.InitBlockUnaligned((void*)buf, 0, (uint)size);
                bool ok = DeviceIoControlSimple(
                    driverHandle,
                    IOCTL_NEXUS_PREBOOT_QUERY,
                    IntPtr.Zero, 0,
                    buf, (uint)size,
                    out uint bytesReturned,
                    IntPtr.Zero);
                if (ok && bytesReturned >= 16)
                {
                    result = Unsafe.AsRef<PrebootScanResult>((void*)buf);
                    return true;
                }
                return false;
            }
            finally
            {
                Marshal.FreeHGlobal(buf);
            }
        }
        catch
        {
            return false;
        }
    }

    public static unsafe bool SendKaResponse(SafeFileHandle driverHandle, uint challenge, uint response)
    {
        if (driverHandle == null || driverHandle.IsInvalid || driverHandle.IsClosed) return false;
        try
        {
            uint* payload = stackalloc uint[2];
            payload[0] = challenge;
            payload[1] = response;
            bool ok = DeviceIoControlSimple(
                driverHandle,
                IOCTL_NEXUS_KA_RESPONSE,
                (IntPtr)payload, 2 * sizeof(uint),
                IntPtr.Zero, 0,
                out _,
                IntPtr.Zero);
            return ok;
        }
        catch
        {
            return false;
        }
    }

    public static bool ActivateWfpBlock(SafeFileHandle driverHandle)
    {
        if (driverHandle == null || driverHandle.IsInvalid || driverHandle.IsClosed) return false;
        try
        {
            bool ok = DeviceIoControlSimple(
                driverHandle,
                IOCTL_NEXUS_WFP_BLOCK,
                IntPtr.Zero, 0,
                IntPtr.Zero, 0,
                out _,
                IntPtr.Zero);
            return ok;
        }
        catch
        {
            return false;
        }
    }

    public static unsafe bool ExchangeBootSeed(SafeFileHandle driverHandle, out byte[] rootKey, out ulong bootSeed)
    {
        rootKey = Array.Empty<byte>();
        bootSeed = 0;
        if (driverHandle == null || driverHandle.IsInvalid || driverHandle.IsClosed) return false;
        try
        {
            int size = Unsafe.SizeOf<NexusBootSeedReply>();
            IntPtr buf = Marshal.AllocHGlobal(size);
            try
            {
                Unsafe.InitBlockUnaligned((void*)buf, 0, (uint)size);
                bool ok = DeviceIoControlSimple(
                    driverHandle,
                    IOCTL_NEXUS_BOOT_SEED_EXCHANGE,
                    IntPtr.Zero, 0,
                    buf, (uint)size,
                    out uint bytesReturned,
                    IntPtr.Zero);
                if (!ok || bytesReturned < (uint)size) return false;
                ref NexusBootSeedReply reply = ref Unsafe.AsRef<NexusBootSeedReply>((void*)buf);
                if (reply.StatusFlags != 1) return false;
                rootKey = new byte[32];
                fixed (byte* dst = rootKey)
                {
                    // RootKey is the first field (Pack=1, offset 0) of the reply buffer.
                    Unsafe.CopyBlockUnaligned(dst, (byte*)buf, 32);
                }
                bootSeed = reply.BootSeed;
                return true;
            }
            finally
            {
                Marshal.FreeHGlobal(buf);
            }
        }
        catch
        {
            return false;
        }
    }

    public static MemoryMappedFile OpenRingBufferSection(string sectionName, long capacity)
    {
        try
        {
            return MemoryMappedFile.OpenExisting(sectionName, MemoryMappedFileRights.ReadWrite);
        }
        catch (Exception)
        {
            // Missing, or owned by another engine instance / denied by ACL (e.g. a Global\
            // section created under a different token). Boot must never die here: try to
            // create the section, and fall back to a private temp-file-backed one if the
            // global namespace is not writable.
            var opts = MemoryMappedFileOptions.None;
            if (Environment.OSVersion.Platform == PlatformID.Win32NT)
            {
                try { return MemoryMappedFile.CreateNew(sectionName, capacity, MemoryMappedFileAccess.ReadWrite, opts, HandleInheritability.None); }
                catch { }
            }
            string temp = Path.Combine(Path.GetTempPath(), "NexusAVRingBuffer_" + Environment.ProcessId + ".tmp");
            return MemoryMappedFile.CreateFromFile(temp, FileMode.OpenOrCreate, null, capacity, MemoryMappedFileAccess.ReadWrite);
        }
    }
}
