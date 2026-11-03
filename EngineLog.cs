using System;
using System.Globalization;
using System.IO;
using System.Text;

namespace NexusAV.Engine;

/// <summary>
/// Rolling file tee for engine stdout/stderr.
///
/// The GUI consumes stdout for the NEXUS_EVENT protocol but never persists it, so a run where
/// something was "detected but not blocked" was undiagnosable once the window closed. This keeps
/// 3 x 5 MB of history under %ProgramData%\NexusXDR\logs.
///
/// Safety rules, because this wraps the channel the GUI depends on:
///  - The console write happens FIRST and is never skipped: a file failure can lose a log line,
///    it can never lose an event the GUI needs.
///  - Nothing here throws into the caller. A logging fault must not take the engine down.
///  - Line ordering inside the file is serialised; the console keeps its own synchronisation.
/// </summary>
public static class EngineLog
{
    private const long MaxBytes = 5 * 1024 * 1024;
    private const int KeepFiles = 3;

    private static readonly object Gate = new();
    private static StreamWriter? _out;
    private static StreamWriter? _err;
    private static long _outBytes;
    private static long _errBytes;
    private static bool _disabled;

    /// <summary>Absolute path of the live log file, or empty when logging could not be enabled.</summary>
    public static string FilePath { get; private set; } = string.Empty;

    public static void Install()
    {
        try
        {
            string dir = ResolveDirectory();
            if (dir.Length == 0)
            {
                _disabled = true;
                return;
            }

            Directory.CreateDirectory(dir);
            FilePath = Path.Combine(dir, "engine.log");
            string errPath = Path.Combine(dir, "engine.error.log");
            Rotate(FilePath);
            Rotate(errPath);

            _out = Open(FilePath);
            _err = Open(errPath);
            if (_out == null || _err == null)
            {
                _disabled = true;
                return;
            }
            _outBytes = _out.BaseStream.Length;
            _errBytes = _err.BaseStream.Length;

            TextWriter consoleOut = Console.Out;
            TextWriter consoleErr = Console.Error;
            Console.SetOut(new TeeWriter(consoleOut, isStdErr: false));
            Console.SetError(new TeeWriter(consoleErr, isStdErr: true));

            WriteRaw(_out, $"===== engine start pid={Environment.ProcessId} utc={DateTime.UtcNow:O} =====");
            Console.Out.Flush();
        }
        catch
        {
            _disabled = true;
            _out = null;
            _err = null;
        }
    }

    private static string ResolveDirectory()
    {
        try
        {
            string common = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
            if (common.Length > 0)
            {
                string probe = NexusDataDir.Ensure("logs");
                // Prove it is really writable — CreateDirectory succeeds on paths we cannot write to
                // when the ACL denies only file creation.
                string test = Path.Combine(probe, ".write-test");
                File.WriteAllText(test, "ok");
                File.Delete(test);
                return probe;
            }
        }
        catch
        {
            // fall through to the per-user location
        }

        try
        {
            string local = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
            if (local.Length == 0) return string.Empty;
            return Path.Combine(local, "NexusXDR", "logs");
        }
        catch
        {
            return string.Empty;
        }
    }

    private static StreamWriter? Open(string path)
    {
        try
        {
            return new StreamWriter(new FileStream(path, FileMode.Append, FileAccess.Write, FileShare.Read),
                new UTF8Encoding(false))
            { AutoFlush = true };
        }
        catch
        {
            return null;
        }
    }

    /// <summary>engine.log -> engine.1.log -> engine.2.log, oldest dropped. Keeps KeepFiles generations.</summary>
    private static void Rotate(string path)
    {
        try
        {
            if (!File.Exists(path) || new FileInfo(path).Length < MaxBytes) return;
            string dir = Path.GetDirectoryName(path) ?? string.Empty;
            string name = Path.GetFileNameWithoutExtension(path);
            string ext = Path.GetExtension(path);
            for (int i = KeepFiles - 1; i >= 1; i--)
            {
                string from = Path.Combine(dir, $"{name}.{i}{ext}");
                string to = Path.Combine(dir, $"{name}.{i + 1}{ext}");
                if (File.Exists(from))
                {
                    if (File.Exists(to)) File.Delete(to);
                    File.Move(from, to);
                }
            }
            string first = Path.Combine(dir, $"{name}.1{ext}");
            if (File.Exists(first)) File.Delete(first);
            File.Move(path, first);
        }
        catch
        {
            // rotation is best-effort; the live writer still appends to whatever exists
        }
    }

    private static void Append(bool isStdErr, string? line)
    {
        if (_disabled) return;
        string text = line ?? string.Empty;
        try
        {
            lock (Gate)
            {
                StreamWriter? w = isStdErr ? _err : _out;
                if (w == null) return;
                WriteRaw(w, text);
                if (isStdErr) _errBytes += text.Length + 32; else _outBytes += text.Length + 32;

                long bytes = isStdErr ? _errBytes : _outBytes;
                if (bytes < MaxBytes) return;

                // Mid-run rotation: close, shift generations, reopen. Bounded so a log flood
                // cannot grow without limit during a long session.
                string path = isStdErr
                    ? Path.Combine(Path.GetDirectoryName(FilePath) ?? string.Empty, "engine.error.log")
                    : FilePath;
                w.Flush();
                w.Dispose();
                Rotate(path);
                StreamWriter? fresh = Open(path);
                if (isStdErr) { _err = fresh; _errBytes = fresh?.BaseStream.Length ?? 0; }
                else { _out = fresh; _outBytes = fresh?.BaseStream.Length ?? 0; }
            }
        }
        catch
        {
            // never let logging break the engine
        }
    }

    private static void WriteRaw(StreamWriter w, string text)
    {
        w.Write(DateTime.Now.ToString("HH:mm:ss.fff", CultureInfo.InvariantCulture));
        w.Write(" | ");
        w.WriteLine(text);
    }

    /// <summary>Flush and release both writers. Called on clean shutdown.</summary>
    public static void Shutdown()
    {
        try
        {
            lock (Gate)
            {
                _out?.Flush();
                _out?.Dispose();
                _err?.Flush();
                _err?.Dispose();
                _out = null;
                _err = null;
                _disabled = true;
            }
        }
        catch
        {
        }
    }

    private sealed class TeeWriter : TextWriter
    {
        private readonly TextWriter _console;
        private readonly bool _isStdErr;

        public TeeWriter(TextWriter console, bool isStdErr)
        {
            _console = console;
            _isStdErr = isStdErr;
        }

        public override Encoding Encoding => _console.Encoding;

        public override void WriteLine(string? value)
        {
            _console.WriteLine(value);   // console first: the GUI must never lose an event
            Append(_isStdErr, value);
        }

        public override void WriteLine()
        {
            _console.WriteLine();
            Append(_isStdErr, string.Empty);
        }

        public override void Write(string? value)
        {
            _console.Write(value);
            if (value != null && value.Length > 0) Append(_isStdErr, value);
        }

        public override void Write(char value)
        {
            _console.Write(value);
        }

        public override void Flush()
        {
            _console.Flush();
        }
    }
}
