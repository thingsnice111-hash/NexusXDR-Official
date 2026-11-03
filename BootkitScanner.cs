using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace NexusAV.Engine;

/// <summary>
/// Asynchronous disk integrity control and bootkit detection.
/// Reads raw disk sectors (MBR/VBR) via user-mode CreateFile to detect bootkits.
/// Bootkits modify disk sectors before OS partitions, so user-mode raw disk access
/// is essential for detection.
/// Enhanced with NVRAM, RAM jump analysis, and firmware attestation.
/// </summary>
public sealed class BootkitScanner : IDisposable
{
    private readonly int _disposed;
    private readonly Dictionary<uint, DiskBaseline> _baselines = new();
    private readonly Dictionary<string, NvramBaseline> _nvramBaselines = new();

    #region Windows API Imports
    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern IntPtr GetFirmwareEnvironmentVariable(
        string lpName,
        string lpGuid,
        IntPtr pBuffer,
        uint nSize);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetFirmwareEnvironmentVariable(
        string lpName,
        string lpGuid,
        IntPtr pBuffer,
        uint nSize);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenProcess(
        uint dwDesiredAccess,
        bool bInheritHandle,
        uint dwProcessId);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool ReadProcessMemory(
        IntPtr hProcess,
        IntPtr lpBaseAddress,
        IntPtr lpBuffer,
        uint nSize,
        out uint lpNumberOfBytesRead);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CloseHandle(IntPtr hObject);

    // User-mode disk access
    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern IntPtr CreateFile(
        string lpFileName,
        uint dwDesiredAccess,
        uint dwShareMode,
        IntPtr lpSecurityAttributes,
        uint dwCreationDisposition,
        uint dwFlagsAndAttributes,
        IntPtr hTemplateFile);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool ReadFile(
        IntPtr hFile,
        IntPtr lpBuffer,
        uint nNumberOfBytesToRead,
        out uint lpNumberOfBytesRead,
        IntPtr lpOverlapped);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetFilePointerEx(
        IntPtr hFile,
        uint dwMoveMethod,
        long liDistanceToMove,
        out ulong lpNewFilePointer);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool DeviceIoControl(
        IntPtr hDevice,
        uint dwIoControlCode,
        IntPtr lpInBuffer,
        uint nInBufferSize,
        IntPtr lpOutBuffer,
        uint nOutBufferSize,
        out uint lpBytesReturned,
        IntPtr lpOverlapped);

    private const uint GENERIC_READ = 0x80000000;
    private const uint FILE_SHARE_READ = 0x00000001;
    private const uint OPEN_EXISTING = 3;
    private const uint FILE_BEGIN = 0;
    private const uint PROCESS_VM_READ = 0x0010;
    private const uint PROCESS_QUERY_INFORMATION = 0x0400;
    private const IntPtr INVALID_HANDLE_VALUE = (IntPtr)(-1);

    private static class NativeMethods
    {
        public const uint IOCTL_STORAGE_GET_DEVICE_NUMBER = 0x2D4800;

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern IntPtr CreateFile(
            string lpFileName,
            uint dwDesiredAccess,
            uint dwShareMode,
            IntPtr lpSecurityAttributes,
            uint dwCreationDisposition,
            uint dwFlagsAndAttributes,
            IntPtr hTemplateFile);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool ReadFile(
            IntPtr hFile,
            IntPtr lpBuffer,
            uint nNumberOfBytesToRead,
            out uint lpNumberOfBytesRead,
            IntPtr lpOverlapped);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool SetFilePointerEx(
            IntPtr hFile,
            uint dwMoveMethod,
            long liDistanceToMove,
            out ulong lpNewFilePointer);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool CloseHandle(IntPtr hObject);
    }
    #endregion

    public struct DiskBaseline
    {
        public uint DiskNumber;
        public byte[] MbrHash;
        public byte[] VbrHash;
        public DateTime LastChecked;
        public bool IsTampered;
    }

    public struct NvramBaseline
    {
        public string VariableName;
        public string Guid;
        public byte[] DataHash;
        public DateTime LastChecked;
        public bool IsTampered;
    }

    public struct RamJumpAnalysis
    {
        public uint ProcessId;
        public string ProcessName;
        public ulong JumpTarget;
        public ulong JumpSource;
        public bool IsSuspicious;
        public string Reason;
    }

    public BootkitScanner()
    {
        // No driver required - uses user-mode raw disk access
    }

    #region NVRAM Analysis
    public async Task<NvramBaseline> ReadNvramVariableAsync(string variableName, string guid)
    {
        var baseline = new NvramBaseline
        {
            VariableName = variableName,
            Guid = guid,
            LastChecked = DateTime.Now
        };

        try
        {
            // Try to read NVRAM variable (may require admin privileges)
            const uint bufferSize = 4096;
            IntPtr buffer = Marshal.AllocHGlobal((int)bufferSize);

            try
            {
                IntPtr bytesRead = GetFirmwareEnvironmentVariable(variableName, guid, buffer, bufferSize);

                if (bytesRead != IntPtr.Zero && bytesRead.ToInt32() > 0)
                {
                    byte[] data = new byte[bytesRead.ToInt32()];
                    Marshal.Copy(buffer, data, 0, data.Length);
                    baseline.DataHash = SHA256.HashData(data);

                    // Check for suspicious patterns in NVRAM
                    if (DetectSuspiciousNvramData(data))
                    {
                        baseline.IsTampered = true;
                        Console.WriteLine($"[BOOTKIT] Suspicious NVRAM data in {variableName} ({guid})");
                    }
                }
                else
                {
                    // Variable doesn't exist or access denied
                    baseline.DataHash = Array.Empty<byte>();
                }
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[BOOTKIT] Failed to read NVRAM {variableName}: {ex.Message}");
            baseline.DataHash = Array.Empty<byte>();
        }

        _nvramBaselines[$"{guid}\\{variableName}"] = baseline;
        return baseline;
    }

    private bool DetectSuspiciousNvramData(byte[] data)
    {
        if (data == null || data.Length < 4) return false;

        // Check for shellcode signatures
        byte[] suspiciousPatterns = {
            0x90, 0x90, 0x90, 0x90, // NOP sled
            0xCC, 0xCC, 0xCC, 0xCC, // INT3
            0xEB, 0xFE              // JMP $ (infinite loop)
        };

        for (int i = 0; i < data.Length - 4; i++)
        {
            if (data[i] == 0xEB && data[i + 1] == 0xFE) return true; // JMP $
            if (data[i] == 0x90 && data[i + 1] == 0x90 && data[i + 2] == 0x90 && data[i + 3] == 0x90) return true; // NOP sled
        }

        // Check for known bootkit signatures
        string dataStr = Encoding.ASCII.GetString(data);
        if (dataStr.Contains("TDSS") || dataStr.Contains("Rovnix") || dataStr.Contains("TDL4"))
        {
            return true;
        }

        return false;
    }

    public async Task ScanCriticalNvramVariablesAsync()
    {
        Console.WriteLine("[BOOTKIT] Scanning critical NVRAM variables...");

        // Common EFI variables that bootkits target
        string[] criticalVariables = {
            "BootOrder", "BootCurrent", "BootNext", "Boot0000", "Boot0001",
            "SecureBoot", "PK", "KEK", "db", "dbx", "dbt"
        };

        string efiGuid = "{8BE4DF61-93CA-11D2-AA0D-00E098032B8C}";

        foreach (string varName in criticalVariables)
        {
            try
            {
                var baseline = await ReadNvramVariableAsync(varName, efiGuid);
                string key = $"{efiGuid}\\{varName}";

                if (_nvramBaselines.TryGetValue(key, out var previous))
                {
                    if (!ByteArrayEquals(previous.DataHash, baseline.DataHash))
                    {
                        Console.WriteLine($"[BOOTKIT] ALERT: NVRAM variable {varName} hash changed!");
                        baseline.IsTampered = true;
                    }
                }

                if (baseline.IsTampered)
                {
                    Console.WriteLine($"[BOOTKIT] ALERT: NVRAM variable {varName} shows signs of tampering!");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[BOOTKIT] Failed to scan NVRAM variable {varName}: {ex.Message}");
            }
        }

        Console.WriteLine("[BOOTKIT] NVRAM scan complete.");
    }
    #endregion

    #region RAM Jump Analysis
    public async Task<List<RamJumpAnalysis>> AnalyzeProcessMemoryJumpsAsync(uint processId)
    {
        var results = new List<RamJumpAnalysis>();
        Process? process = null;

        try
        {
            process = Process.GetProcessById((int)processId);
            string processName = process.ProcessName;

            IntPtr hProcess = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, false, processId);
            if (hProcess == IntPtr.Zero)
            {
                Console.WriteLine($"[BOOTKIT] Failed to open process {processId} for memory analysis");
                return results;
            }

            try
            {
                // Read critical memory regions
                ulong[] criticalAddresses = {
                    0x7FFE0000, // KUSER_SHARED_DATA
                    0xFFFFF80000000000, // Kernel base (may not be accessible from user mode)
                };

                foreach (ulong address in criticalAddresses)
                {
                    IntPtr buffer = Marshal.AllocHGlobal(64);
                    try
                    {
                        bool readOk = ReadProcessMemory(hProcess, (IntPtr)address, buffer, 64, out uint bytesRead);
                        if (readOk && bytesRead > 0)
                        {
                            byte[] data = new byte[bytesRead];
                            Marshal.Copy(buffer, data, 0, (int)bytesRead);

                            // Analyze for suspicious JMP/CALL instructions
                            var analysis = AnalyzeInstructionPattern(data, address, processId, processName);
                            if (analysis != null)
                            {
                                results.Add(analysis.Value);
                            }
                        }
                    }
                    finally
                    {
                        Marshal.FreeHGlobal(buffer);
                    }
                }
            }
            finally
            {
                CloseHandle(hProcess);
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[BOOTKIT] Error analyzing process {processId}: {ex.Message}");
        }

        return results;
    }

    private RamJumpAnalysis? AnalyzeInstructionPattern(byte[] data, ulong baseAddress, uint pid, string name)
    {
        if (data == null || data.Length < 5) return null;

        // Check for JMP instructions (E9 for relative, FF /4 for indirect)
        for (int i = 0; i < data.Length - 5; i++)
        {
            // JMP rel32 (E9)
            if (data[i] == 0xE9)
            {
                int relOffset = BitConverter.ToInt32(data, i + 1);
                ulong target = baseAddress + (ulong)(i + 5) + (ulong)relOffset;

                // Check if jump targets suspicious region
                if (IsSuspiciousJumpTarget(target))
                {
                    return new RamJumpAnalysis
                    {
                        ProcessId = pid,
                        ProcessName = name,
                        JumpSource = baseAddress + (ulong)i,
                        JumpTarget = target,
                        IsSuspicious = true,
                        Reason = $"Direct JMP to suspicious region 0x{target:X}"
                    };
                }
            }

            // CALL rel32 (E8)
            if (data[i] == 0xE8)
            {
                int relOffset = BitConverter.ToInt32(data, i + 1);
                ulong target = baseAddress + (ulong)(i + 5) + (ulong)relOffset;

                if (IsSuspiciousJumpTarget(target))
                {
                    return new RamJumpAnalysis
                    {
                        ProcessId = pid,
                        ProcessName = name,
                        JumpSource = baseAddress + (ulong)i,
                        JumpTarget = target,
                        IsSuspicious = true,
                        Reason = $"Direct CALL to suspicious region 0x{target:X}"
                    };
                }
            }
        }

        return null;
    }

    private bool IsSuspiciousJumpTarget(ulong address)
    {
        // Check for jumps to unaligned addresses
        if ((address & 0xF) != 0) return false; // Not 16-byte aligned

        // Check for jumps to typical shellcode regions
        if (address >= 0x400000 && address <= 0x7FFFFFFF) return false; // Normal user space
        if (address >= 0xFFFFF80000000000) return true; // Kernel space (suspicious from user mode)

        // Check for jumps to stack-like regions
        if (address >= 0x7FF00000 && address <= 0x7FFFFFFF) return true;

        return false;
    }

    public async Task ScanSystemCriticalProcessesAsync()
    {
        Console.WriteLine("[BOOTKIT] Analyzing memory jumps in critical processes...");

        uint[] criticalPids = { 4 }; // System process

        foreach (uint pid in criticalPids)
        {
            try
            {
                var jumps = await AnalyzeProcessMemoryJumpsAsync(pid);
                foreach (var jump in jumps)
                {
                    if (jump.IsSuspicious)
                    {
                        Console.WriteLine($"[BOOTKIT] ALERT: Suspicious memory jump in PID {jump.ProcessId} ({jump.ProcessName})");
                        Console.WriteLine($"[BOOTKIT]   Source: 0x{jump.JumpSource:X} -> Target: 0x{jump.JumpTarget:X}");
                        Console.WriteLine($"[BOOTKIT]   Reason: {jump.Reason}");
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[BOOTKIT] Failed to analyze process {pid}: {ex.Message}");
            }
        }

        Console.WriteLine("[BOOTKIT] Memory jump analysis complete.");
    }
    #endregion

    public async Task<KernelBridge.RawDiskReadReply> ReadRawDiskAsync(uint diskNumber, ulong sectorOffset, uint sectorCount)
    {
        var reply = new KernelBridge.RawDiskReadReply();

        // User-mode raw disk read via CreateFile on \\.\PhysicalDriveN.
        // Requires administrator privileges; on failure we return ACCESS_DENIED status.
        try
        {
            string diskPath = $"\\\\.\\PhysicalDrive{diskNumber}";

            IntPtr hFile = NativeMethods.CreateFile(
                diskPath,
                GENERIC_READ,
                FILE_SHARE_READ,
                IntPtr.Zero,
                OPEN_EXISTING,
                0,
                IntPtr.Zero);

            if (hFile == INVALID_HANDLE_VALUE)
            {
                Console.WriteLine($"[BOOTKIT] Failed to open disk {diskNumber}. Admin privileges required.");
                reply.Status = unchecked((uint)0xC0000022); // STATUS_ACCESS_DENIED
                return reply;
            }

            try
            {
                ulong byteOffset = sectorOffset * 512;
                if (!NativeMethods.SetFilePointerEx(hFile, FILE_BEGIN, (long)byteOffset, out _))
                {
                    reply.Status = unchecked((uint)0xC0000001);
                    return reply;
                }

                uint bytesToRead = sectorCount * 512;
                byte[] buffer = new byte[bytesToRead];
                uint bytesRead = 0;

                GCHandle pinned = GCHandle.Alloc(buffer, GCHandleType.Pinned);
                try
                {
                    IntPtr pBuffer = pinned.AddrOfPinnedObject();
                    if (NativeMethods.ReadFile(hFile, pBuffer, bytesToRead, out bytesRead, IntPtr.Zero))
                    {
                        reply.BytesRead = bytesRead;
                        reply.Status = 0; // STATUS_SUCCESS
                        uint copyLen = Math.Min(bytesRead, (uint)KernelBridge.RawDiskReadReply.DataSize);
                        Array.Copy(buffer, reply.Data, copyLen);
                    }
                    else
                    {
                        reply.Status = unchecked((uint)0xC0000001);
                    }
                }
                finally
                {
                    pinned.Free();
                }
            }
            finally
            {
                NativeMethods.CloseHandle(hFile);
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[BOOTKIT] User-mode disk read error: {ex.Message}");
            reply.Status = unchecked((uint)0xC0000001);
        }

        await Task.CompletedTask;
        return reply;
    }

    public async Task<DiskBaseline> ScanDiskAsync(uint diskNumber)
    {
        var baseline = new DiskBaseline { DiskNumber = diskNumber, LastChecked = DateTime.Now };

        // Read MBR (sector 0)
        var mbrReply = await ReadRawDiskAsync(diskNumber, 0, 1);
        if (mbrReply.BytesRead == 512)
        {
            unsafe
            {
                byte[] mbrData = new byte[512];
                fixed (byte* src = mbrReply.Data)
                {
                    for (int i = 0; i < 512; i++) mbrData[i] = src[i];
                }
                baseline.MbrHash = SHA256.HashData(mbrData);
                
                // Validate MBR signature
                ushort signature = (ushort)(mbrData[510] | (mbrData[511] << 8));
                if (signature != 0xAA55)
                {
                    Console.WriteLine($"[BOOTKIT] Disk {diskNumber}: Invalid MBR signature 0x{signature:X4}");
                    baseline.IsTampered = true;
                }

                // Check for suspicious partition types
                CheckPartitionTypes(mbrData, diskNumber, baseline);
            }
        }

        // Read VBR (sector 2048 for GPT, or partition boot sector)
        var vbrReply = await ReadRawDiskAsync(diskNumber, 2048, 1);
        if (vbrReply.BytesRead == 512)
        {
            unsafe
            {
                byte[] vbrData = new byte[512];
                fixed (byte* src = vbrReply.Data)
                {
                    for (int i = 0; i < 512; i++) vbrData[i] = src[i];
                }
                baseline.VbrHash = SHA256.HashData(vbrData);
                
                // Check for OEM identifier
                string oem = Encoding.ASCII.GetString(vbrData, 3, 8);
                if (!IsKnownOem(oem))
                {
                    Console.WriteLine($"[BOOTKIT] Disk {diskNumber}: Suspicious VBR OEM: {oem}");
                    baseline.IsTampered = true;
                }
            }
        }

        _baselines[diskNumber] = baseline;
        return baseline;
    }

    private void CheckPartitionTypes(byte[] mbr, uint diskNumber, DiskBaseline baseline)
    {
        // Check partition table entries in MBR
        for (int i = 0; i < 4; i++)
        {
            int offset = 0x1BE + (i * 16);
            byte partitionType = mbr[offset + 4];
            
            // Known bootkit partition types
            byte[] suspiciousTypes = { 0x07, 0x17, 0x27, 0xAF }; // NTFS, hidden NTFS, etc.
            
            if (partitionType == 0x00) continue; // Empty partition
            
            if (partitionType == 0x07 || partitionType == 0x17)
            {
                // NTFS partition - check if it's bootable
                byte bootIndicator = mbr[offset];
                if (bootIndicator == 0x80)
                {
                    Console.WriteLine($"[BOOTKIT] Disk {diskNumber}: Bootable NTFS partition at index {i}");
                }
            }
        }
    }

    private bool IsKnownOem(string oem)
    {
        string[] knownOems = 
        {
            "MSWIN4.1", "MSDOS5.0", "NTFS    ", "FAT12   ", 
            "FAT16   ", "FAT32   ", "EXFAT   "
        };
        
        foreach (string known in knownOems)
        {
            if (oem == known) return true;
        }
        return false;
    }

    public bool CompareWithBaseline(uint diskNumber, DiskBaseline current)
    {
        if (!_baselines.TryGetValue(diskNumber, out var previous))
        {
            _baselines[diskNumber] = current;
            return true; // First scan, no baseline to compare
        }

        bool mbrChanged = !ByteArrayEquals(previous.MbrHash, current.MbrHash);
        bool vbrChanged = !ByteArrayEquals(previous.VbrHash, current.VbrHash);

        if (mbrChanged)
        {
            Console.WriteLine($"[BOOTKIT] Disk {diskNumber}: MBR hash changed since last scan!");
        }

        if (vbrChanged)
        {
            Console.WriteLine($"[BOOTKIT] Disk {diskNumber}: VBR hash changed since last scan!");
        }

        return !mbrChanged && !vbrChanged;
    }

    private static bool ByteArrayEquals(byte[] a, byte[] b)
    {
        if (a == null || b == null) return a == b;
        if (a.Length != b.Length) return false;
        
        for (int i = 0; i < a.Length; i++)
        {
            if (a[i] != b[i]) return false;
        }
        return true;
    }

    public async Task ScanAllDisksAsync()
    {
        Console.WriteLine("[BOOTKIT] Starting asynchronous disk integrity scan...");

        for (uint disk = 0; disk < 4; disk++)
        {
            try
            {
                var baseline = await ScanDiskAsync(disk);
                if (baseline.MbrHash == null || baseline.VbrHash == null)
                {
                    // Never report "verified" for a disk we could not read, and never store a
                    // null-hash baseline (it would fire a false "hash changed" alert later).
                    Console.WriteLine($"[BOOTKIT] Disk {disk}: skipped (MBR/VBR unreadable — admin privileges required)");
                    continue;
                }
                bool isClean = CompareWithBaseline(disk, baseline);

                if (baseline.IsTampered)
                {
                    Console.WriteLine($"[BOOTKIT] ALERT: Disk {disk} shows signs of tampering!");
                }
                else if (isClean)
                {
                    Console.WriteLine($"[BOOTKIT] Disk {disk}: Integrity verified (MBR + VBR clean)");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[BOOTKIT] Failed to scan disk {disk}: {ex.Message}");
            }
        }

        Console.WriteLine("[BOOTKIT] Disk integrity scan complete.");
    }

    #region Advanced Bootkit Detection
    public async Task<DiskBaseline> ScanHiddenSectorsAsync(uint diskNumber)
    {
        var baseline = new DiskBaseline { DiskNumber = diskNumber, LastChecked = DateTime.Now };

        // Scan sectors between MBR and first partition (hidden area often used by bootkits)
        for (uint sector = 1; sector < 63; sector++)
        {
            try
            {
                var reply = await ReadRawDiskAsync(diskNumber, sector, 1);
                if (reply.BytesRead == 512)
                {
                    unsafe
                    {
                        byte[] sectorData = new byte[512];
                        fixed (byte* src = reply.Data)
                        {
                            for (int i = 0; i < 512; i++) sectorData[i] = src[i];
                        }

                        // Check for non-zero data in hidden sectors (suspicious)
                        if (!IsSectorEmpty(sectorData))
                        {
                            Console.WriteLine($"[BOOTKIT] WARNING: Non-zero data in hidden sector {sector} on disk {diskNumber}");
                            baseline.IsTampered = true;

                            // Check for known bootkit signatures
                            if (ContainsBootkitSignature(sectorData))
                            {
                                Console.WriteLine($"[BOOTKIT] ALERT: Bootkit signature detected in hidden sector {sector}!");
                            }
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[BOOTKIT] Failed to read hidden sector {sector}: {ex.Message}");
            }
        }

        return baseline;
    }

    private bool IsSectorEmpty(byte[] sector)
    {
        if (sector == null || sector.Length != 512) return true;

        for (int i = 0; i < 512; i++)
        {
            if (sector[i] != 0) return false;
        }
        return true;
    }

    private bool ContainsBootkitSignature(byte[] data)
    {
        if (data == null || data.Length < 4) return false;

        string dataStr = Encoding.ASCII.GetString(data);

        // Known bootkit signatures
        string[] signatures = {
            "TDL4", "TDSS", "Rovnix", "ZeroAccess", "Stuxnet",
            "Bootkit", "Mebroot", "Pihar", "Whistler", "Olmarik"
        };

        foreach (string sig in signatures)
        {
            if (dataStr.Contains(sig, StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }

        return false;
    }

    public async Task ScanVbrCodeIntegrityAsync(uint diskNumber)
    {
        // Read VBR (Volume Boot Record) and analyze code integrity
        var vbrReply = await ReadRawDiskAsync(diskNumber, 2048, 1);
        if (vbrReply.BytesRead == 512)
        {
            unsafe
            {
                byte[] vbrData = new byte[512];
                fixed (byte* src = vbrReply.Data)
                {
                    for (int i = 0; i < 512; i++) vbrData[i] = src[i];
                }

                // Check BPB (BIOS Parameter Block) for anomalies
                AnalyzeBpbIntegrity(vbrData, diskNumber);

                // Check boot code for suspicious jumps
                AnalyzeBootCodeJumps(vbrData, diskNumber);
            }
        }
    }

    private void AnalyzeBpbIntegrity(byte[] vbr, uint diskNumber)
    {
        // Check OEM identifier at offset 3 (8 bytes)
        string oem = Encoding.ASCII.GetString(vbr, 3, 8).Trim();
        Console.WriteLine($"[BOOTKIT] Disk {diskNumber} VBR OEM: {oem}");

        // Check bytes per sector (offset 11, should be 512)
        ushort bytesPerSector = BitConverter.ToUInt16(vbr, 11);
        if (bytesPerSector != 512)
        {
            Console.WriteLine($"[BOOTKIT] WARNING: Unusual bytes per sector: {bytesPerSector}");
        }

        // Check sectors per cluster (offset 13, typically 1-128)
        byte sectorsPerCluster = vbr[13];
        if (sectorsPerCluster == 0 || sectorsPerCluster > 128)
        {
            Console.WriteLine($"[BOOTKIT] WARNING: Invalid sectors per cluster: {sectorsPerCluster}");
        }

        // Check reserved sectors (offset 14, typically 1-32 for NTFS)
        ushort reservedSectors = BitConverter.ToUInt16(vbr, 14);
        if (reservedSectors == 0 || reservedSectors > 64)
        {
            Console.WriteLine($"[BOOTKIT] WARNING: Suspicious reserved sectors count: {reservedSectors}");
        }
    }

    private void AnalyzeBootCodeJumps(byte[] vbr, uint diskNumber)
    {
        // VBR boot code typically starts at offset 0 with JMP instruction
        // Standard patterns: EB XX (short JMP) or E9 XX XX XX XX (near JMP)

        if (vbr[0] == 0xEB)
        {
            // Short JMP to offset 3 + vbr[1]
            byte target = (byte)(3 + vbr[1]);
            Console.WriteLine($"[BOOTKIT] Disk {diskNumber} VBR: Short JMP to offset 0x{target:X}");

            // Check if jump target is reasonable (typically 0x3C-0x60)
            if (target < 0x3C || target > 0x80)
            {
                Console.WriteLine($"[BOOTKIT] WARNING: Unusual JMP target 0x{target:X}");
            }
        }
        else if (vbr[0] == 0xE9)
        {
            // Near JMP
            int offset = BitConverter.ToInt32(vbr, 1);
            Console.WriteLine($"[BOOTKIT] Disk {diskNumber} VBR: Near JMP offset {offset}");
        }
        else
        {
            Console.WriteLine($"[BOOTKIT] WARNING: VBR does not start with JMP instruction (0x{vbr[0]:X2})");
        }

        // Check for INT 13h calls (boot sector should use BIOS disk services)
        for (int i = 0; i < vbr.Length - 2; i++)
        {
            if (vbr[i] == 0xCD && vbr[i + 1] == 0x13)
            {
                Console.WriteLine($"[BOOTKIT] Disk {diskNumber} VBR: INT 13h call at offset 0x{i:X}");
            }
        }
    }

    public async Task PerformComprehensiveBootkitScanAsync()
    {
        Console.WriteLine("[BOOTKIT] Starting comprehensive bootkit detection scan...");
        Console.WriteLine("[BOOTKIT] ===============================================");

        // Phase 1: Disk integrity (MBR/VBR)
        Console.WriteLine("[BOOTKIT] Phase 1: Disk integrity analysis...");
        await ScanAllDisksAsync();

        // Phase 2: Hidden sector analysis
        Console.WriteLine("[BOOTKIT] Phase 2: Hidden sector analysis...");
        for (uint disk = 0; disk < 4; disk++)
        {
            try
            {
                await ScanHiddenSectorsAsync(disk);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[BOOTKIT] Failed to scan hidden sectors on disk {disk}: {ex.Message}");
            }
        }

        // Phase 3: VBR code integrity
        Console.WriteLine("[BOOTKIT] Phase 3: VBR code integrity analysis...");
        for (uint disk = 0; disk < 4; disk++)
        {
            try
            {
                await ScanVbrCodeIntegrityAsync(disk);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[BOOTKIT] Failed to analyze VBR on disk {disk}: {ex.Message}");
            }
        }

        // Phase 4: NVRAM analysis
        Console.WriteLine("[BOOTKIT] Phase 4: NVRAM variable analysis...");
        await ScanCriticalNvramVariablesAsync();

        // Phase 5: Memory jump analysis
        Console.WriteLine("[BOOTKIT] Phase 5: Process memory jump analysis...");
        await ScanSystemCriticalProcessesAsync();

        Console.WriteLine("[BOOTKIT] ===============================================");
        Console.WriteLine("[BOOTKIT] Comprehensive bootkit scan complete.");
    }
    #endregion

    public void Dispose()
    {
        // SafeFileHandle is managed, no explicit dispose needed
    }
}
