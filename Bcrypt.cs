using System;
using System.IO;
using System.Runtime.InteropServices;

namespace NexusAV.Engine;

public static unsafe partial class BcryptSha256
{
    public const uint BCRYPT_SHA256_ALGORITHM = 0x00000001;

    [LibraryImport("bcrypt.dll", StringMarshalling = StringMarshalling.Utf16)]
    public static partial int BCryptOpenAlgorithmProvider(out IntPtr phAlgorithm, string pszAlgId, string? pszImplementation, uint dwFlags);

    [LibraryImport("bcrypt.dll")]
    public static partial int BCryptCreateHash(IntPtr hAlgorithm, out IntPtr phHash, IntPtr pbHashObject, uint cbHashObject, IntPtr pbSecret, uint cbSecret, uint dwFlags);

    [LibraryImport("bcrypt.dll")]
    public static partial int BCryptHashData(IntPtr hHash, byte* pbInput, int cbInput, uint dwFlags);

    [LibraryImport("bcrypt.dll")]
    public static partial int BCryptFinishHash(IntPtr hHash, byte* pbOutput, int cbOutput, uint dwFlags);

    [LibraryImport("bcrypt.dll")]
    public static partial int BCryptDestroyHash(IntPtr hHash);

    [LibraryImport("bcrypt.dll")]
    public static partial int BCryptCloseAlgorithmProvider(IntPtr hAlgorithm, uint dwFlags);

    public static byte[] HashFile(string path)
    {
        const int STATUS_SUCCESS = 0;
        const int SHA256_HASH_SIZE = 32;
        const int CHUNK_SIZE = 1024 * 1024;

        IntPtr hAlgorithm = IntPtr.Zero;
        IntPtr hHash = IntPtr.Zero;
        byte[] result = new byte[SHA256_HASH_SIZE];

        try
        {
            int ntStatus = BCryptOpenAlgorithmProvider(out hAlgorithm, "SHA256", null, 0);
            if (ntStatus != STATUS_SUCCESS || hAlgorithm == IntPtr.Zero)
            {
                throw new InvalidOperationException($"BCryptOpenAlgorithmProvider failed: 0x{ntStatus:X8}");
            }

            ntStatus = BCryptCreateHash(hAlgorithm, out hHash, IntPtr.Zero, 0, IntPtr.Zero, 0, 0);
            if (ntStatus != STATUS_SUCCESS || hHash == IntPtr.Zero)
            {
                throw new InvalidOperationException($"BCryptCreateHash failed: 0x{ntStatus:X8}");
            }

            using (FileStream fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite, CHUNK_SIZE, false))
            {
                byte[] buffer = new byte[CHUNK_SIZE];
                int bytesRead;
                while ((bytesRead = fs.Read(buffer, 0, buffer.Length)) > 0)
                {
                    fixed (byte* pBuf = buffer)
                    {
                        ntStatus = BCryptHashData(hHash, pBuf, bytesRead, 0);
                        if (ntStatus != STATUS_SUCCESS)
                        {
                            throw new InvalidOperationException($"BCryptHashData failed: 0x{ntStatus:X8}");
                        }
                    }
                }
            }

            fixed (byte* pResult = result)
            {
                ntStatus = BCryptFinishHash(hHash, pResult, SHA256_HASH_SIZE, 0);
                if (ntStatus != STATUS_SUCCESS)
                {
                    throw new InvalidOperationException($"BCryptFinishHash failed: 0x{ntStatus:X8}");
                }
            }

            return result;
        }
        finally
        {
            if (hHash != IntPtr.Zero)
            {
                try { BCryptDestroyHash(hHash); } catch { }
            }
            if (hAlgorithm != IntPtr.Zero)
            {
                try { BCryptCloseAlgorithmProvider(hAlgorithm, 0); } catch { }
            }
        }
    }
}
