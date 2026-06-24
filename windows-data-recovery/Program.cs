using System.IO;
using Microsoft.Win32.SafeHandles;

if (args.Length == 0 || args[0] is "-h" or "--help" or "help")
{
    PrintHelp();
    return 0;
}

try
{
    return args[0].ToLowerInvariant() switch
    {
        "list" => RecoveryMvp.DriveLister.List(),
        "scan" => RunScan(args.Skip(1).ToArray()),
        _ => Fail($"Unknown command '{args[0]}'.")
    };
}
catch (Exception ex)
{
    Console.Error.WriteLine($"Error: {ex.Message}");
    return 1;
}

static int RunScan(string[] args)
{
    var options = RecoveryMvp.ScanOptions.Parse(args);
    if (options is null)
    {
        PrintScanUsage();
        return 2;
    }

    Directory.CreateDirectory(options.OutputDirectory);

    if (RecoveryMvp.PathSafety.OutputLooksLikeSource(options.Source, options.OutputDirectory))
    {
        return Fail("Refusing to recover to the same drive/source. Choose an output folder on another disk.");
    }

    using var source = RecoveryMvp.SourceOpener.OpenReadOnly(options.Source);
    var scanner = new RecoveryMvp.SignatureScanner(RecoveryMvp.FileSignatures.All);

    Console.WriteLine($"Source: {options.Source}");
    Console.WriteLine($"Output: {options.OutputDirectory}");
    Console.WriteLine("Mode: read-only deep signature scan");
    Console.WriteLine();

    var count = scanner.Scan(source.Stream, options.OutputDirectory, options.MaxBytesPerFile);

    Console.WriteLine();
    Console.WriteLine($"Recovered candidates: {count}");
    Console.WriteLine("Review confidence percentages before trusting restored files.");
    return 0;
}

static int Fail(string message)
{
    Console.Error.WriteLine(message);
    return 1;
}

static void PrintHelp()
{
    Console.WriteLine("Windows Data Recovery MVP");
    Console.WriteLine();
    Console.WriteLine("Commands:");
    Console.WriteLine("  list");
    Console.WriteLine("  scan --source <path-or-device> --output <folder> [--max-file-mb <number>]");
    Console.WriteLine();
    PrintScanUsage();
}

static void PrintScanUsage()
{
    Console.WriteLine("Examples:");
    Console.WriteLine(@"  dotnet run -- list");
    Console.WriteLine(@"  dotnet run -- scan --source ""\\.\E:"" --output ""D:\Recovered""");
    Console.WriteLine(@"  dotnet run -- scan --source ""C:\images\usb.img"" --output ""D:\Recovered"" --max-file-mb 512");
}

namespace RecoveryMvp
{
    internal sealed record ScanOptions(string Source, string OutputDirectory, long MaxBytesPerFile)
    {
        public static ScanOptions? Parse(string[] args)
        {
            string? source = null;
            string? output = null;
            long maxBytes = 256L * 1024L * 1024L;

            for (var i = 0; i < args.Length; i++)
            {
                switch (args[i])
                {
                    case "--source" when i + 1 < args.Length:
                        source = args[++i];
                        break;
                    case "--output" when i + 1 < args.Length:
                        output = args[++i];
                        break;
                    case "--max-file-mb" when i + 1 < args.Length && long.TryParse(args[++i], out var mb):
                        maxBytes = Math.Max(1, mb) * 1024L * 1024L;
                        break;
                    default:
                        return null;
                }
            }

            return string.IsNullOrWhiteSpace(source) || string.IsNullOrWhiteSpace(output)
                ? null
                : new ScanOptions(source, output, maxBytes);
        }
    }

    internal static class DriveLister
    {
        public static int List()
        {
            foreach (var drive in DriveInfo.GetDrives())
            {
                var format = drive.IsReady ? drive.DriveFormat : "";
                var status = drive.IsReady ? $"{FormatBytes(drive.AvailableFreeSpace)} free / {FormatBytes(drive.TotalSize)}" : "not ready";
                var label = drive.IsReady ? drive.VolumeLabel : "";
                Console.WriteLine($"{drive.Name,-8} {drive.DriveType,-12} {format,-8} {status} {label}");
                Console.WriteLine($@"         scan source: \\.\{drive.Name.TrimEnd('\')}");
            }

            return 0;
        }

        private static string FormatBytes(long value)
        {
            string[] units = ["B", "KB", "MB", "GB", "TB"];
            double size = value;
            var unit = 0;
            while (size >= 1024 && unit < units.Length - 1)
            {
                size /= 1024;
                unit++;
            }

            return $"{size:0.##} {units[unit]}";
        }
    }

    internal static class PathSafety
    {
        public static bool OutputLooksLikeSource(string source, string outputDirectory)
        {
            var outputRoot = Path.GetPathRoot(Path.GetFullPath(outputDirectory));
            if (string.IsNullOrWhiteSpace(outputRoot))
            {
                return false;
            }

            if (source.StartsWith(@"\\.\", StringComparison.OrdinalIgnoreCase) && source.Length >= 6)
            {
                var sourceLetter = char.ToUpperInvariant(source[4]);
                var outputLetter = char.ToUpperInvariant(outputRoot[0]);
                return sourceLetter == outputLetter;
            }

            var sourceRoot = Path.GetPathRoot(Path.GetFullPath(source));
            return string.Equals(sourceRoot, outputRoot, StringComparison.OrdinalIgnoreCase);
        }
    }

    internal sealed class OpenedSource : IDisposable
    {
        private readonly SafeFileHandle? _handle;

        public OpenedSource(Stream stream, SafeFileHandle? handle = null)
        {
            Stream = stream;
            _handle = handle;
        }

        public Stream Stream { get; }

        public void Dispose()
        {
            Stream.Dispose();
            _handle?.Dispose();
        }
    }

    internal static class SourceOpener
    {
        public static OpenedSource OpenReadOnly(string source)
        {
            if (source.StartsWith(@"\\.\", StringComparison.OrdinalIgnoreCase))
            {
                var handle = NativeMethods.CreateFile(
                    source,
                    NativeMethods.GenericRead,
                    NativeMethods.FileShareRead | NativeMethods.FileShareWrite,
                    IntPtr.Zero,
                    NativeMethods.OpenExisting,
                    NativeMethods.FileAttributeNormal | NativeMethods.FileFlagSequentialScan,
                    IntPtr.Zero);

                if (handle.IsInvalid)
                {
                    throw new IOException($"Could not open '{source}'. Run as Administrator and make sure no recovery output points to this drive.");
                }

                return new OpenedSource(new FileStream(handle, FileAccess.Read, 1024 * 1024, isAsync: false), handle);
            }

            return new OpenedSource(new FileStream(source, FileMode.Open, FileAccess.Read, FileShare.Read, 1024 * 1024, FileOptions.SequentialScan));
        }
    }

    internal static class NativeMethods
    {
        public const uint GenericRead = 0x80000000;
        public const uint FileShareRead = 0x00000001;
        public const uint FileShareWrite = 0x00000002;
        public const uint OpenExisting = 3;
        public const uint FileAttributeNormal = 0x00000080;
        public const uint FileFlagSequentialScan = 0x08000000;

        [System.Runtime.InteropServices.DllImport("kernel32.dll", SetLastError = true, CharSet = System.Runtime.InteropServices.CharSet.Unicode)]
        public static extern SafeFileHandle CreateFile(
            string lpFileName,
            uint dwDesiredAccess,
            uint dwShareMode,
            IntPtr lpFileSecurityAttributes,
            uint dwCreationDisposition,
            uint dwFlagsAndAttributes,
            IntPtr hTemplateFile);
    }

    internal sealed record FileSignature(
        string Name,
        string Extension,
        byte[] Header,
        byte[]? Footer,
        long DefaultMaxBytes);

    internal static class FileSignatures
    {
        public static IReadOnlyList<FileSignature> All { get; } =
        [
            new("jpeg", ".jpg", [0xFF, 0xD8, 0xFF], [0xFF, 0xD9], 64L * 1024L * 1024L),
            new("png", ".png", [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A], [0x49, 0x45, 0x4E, 0x44, 0xAE, 0x42, 0x60, 0x82], 64L * 1024L * 1024L),
            new("pdf", ".pdf", [0x25, 0x50, 0x44, 0x46, 0x2D], [0x25, 0x25, 0x45, 0x4F, 0x46], 128L * 1024L * 1024L),
            new("gif", ".gif", [0x47, 0x49, 0x46, 0x38], [0x00, 0x3B], 32L * 1024L * 1024L),
            new("zip-office", ".zip", [0x50, 0x4B, 0x03, 0x04], [0x50, 0x4B, 0x05, 0x06], 256L * 1024L * 1024L)
        ];
    }

    internal sealed class SignatureScanner
    {
        private const int BufferSize = 1024 * 1024;
        private readonly IReadOnlyList<FileSignature> _signatures;
        private readonly int _maxSignatureLength;

        public SignatureScanner(IReadOnlyList<FileSignature> signatures)
        {
            _signatures = signatures;
            _maxSignatureLength = signatures.Max(s => Math.Max(s.Header.Length, s.Footer?.Length ?? 0));
        }

        public int Scan(Stream source, string outputDirectory, long maxBytesPerFile)
        {
            var buffer = new byte[BufferSize + _maxSignatureLength];
            var carry = 0;
            long absoluteOffset = 0;
            var recovered = 0;

            while (true)
            {
                var read = source.Read(buffer, carry, BufferSize);
                if (read == 0)
                {
                    break;
                }

                var available = carry + read;
                var scanLimit = available - _maxSignatureLength;
                for (var i = 0; i <= scanLimit; i++)
                {
                    var span = buffer.AsSpan(i, available - i);
                    var signature = FindHeader(span);
                    if (signature is null)
                    {
                        continue;
                    }

                    var fileOffset = absoluteOffset + i - carry;
                    var limit = Math.Min(maxBytesPerFile, signature.DefaultMaxBytes);
                    var result = RecoverCandidate(source, signature, outputDirectory, fileOffset, limit, ++recovered);
                    Console.WriteLine($"{Path.GetFileName(result.Path),-32} {signature.Name,-10} offset=0x{fileOffset:X} confidence={result.ConfidencePercent}% bytes={result.BytesWritten}");
                }

                carry = Math.Min(_maxSignatureLength, available);
                buffer.AsSpan(available - carry, carry).CopyTo(buffer);
                absoluteOffset += read;
            }

            return recovered;
        }

        private FileSignature? FindHeader(ReadOnlySpan<byte> span)
        {
            foreach (var signature in _signatures)
            {
                if (span.Length >= signature.Header.Length && span[..signature.Header.Length].SequenceEqual(signature.Header))
                {
                    return signature;
                }
            }

            return null;
        }

        private static RecoveryResult RecoverCandidate(Stream source, FileSignature signature, string outputDirectory, long fileOffset, long maxBytes, int index)
        {
            var fileName = $"{index:000000}_{signature.Name}_{fileOffset:X}{signature.Extension}";
            var path = Path.Combine(outputDirectory, fileName);

            var originalPosition = source.CanSeek ? source.Position : 0;
            if (source.CanSeek)
            {
                source.Position = fileOffset;
            }

            long written = 0;
            var footerFound = false;
            var tail = new Queue<byte>();

            using (var output = new FileStream(path, FileMode.CreateNew, FileAccess.Write, FileShare.None))
            {
                var buffer = new byte[64 * 1024];
                while (written < maxBytes)
                {
                    var wanted = (int)Math.Min(buffer.Length, maxBytes - written);
                    var read = source.Read(buffer, 0, wanted);
                    if (read == 0)
                    {
                        break;
                    }

                    var writeCount = read;
                    if (signature.Footer is not null && TryFindFooter(buffer.AsSpan(0, read), tail, signature.Footer, out var footerEndIndex))
                    {
                        writeCount = footerEndIndex + 1;
                        footerFound = true;
                    }

                    output.Write(buffer, 0, writeCount);
                    written += writeCount;

                    if (footerFound)
                    {
                        break;
                    }
                }
            }

            if (source.CanSeek)
            {
                source.Position = originalPosition;
            }

            var confidence = EstimateConfidence(signature, footerFound, written, maxBytes);
            return new RecoveryResult(path, written, confidence);
        }

        private static bool TryFindFooter(ReadOnlySpan<byte> chunk, Queue<byte> tail, byte[] footer, out int footerEndIndex)
        {
            for (var i = 0; i < chunk.Length; i++)
            {
                tail.Enqueue(chunk[i]);
                while (tail.Count > footer.Length)
                {
                    tail.Dequeue();
                }

                if (tail.Count == footer.Length && tail.SequenceEqual(footer))
                {
                    footerEndIndex = i;
                    return true;
                }
            }

            footerEndIndex = -1;
            return false;
        }

        private static int EstimateConfidence(FileSignature signature, bool footerFound, long written, long maxBytes)
        {
            if (footerFound)
            {
                return signature.Name == "zip-office" ? 70 : 85;
            }

            if (written >= maxBytes)
            {
                return 35;
            }

            return 50;
        }
    }

    internal sealed record RecoveryResult(string Path, long BytesWritten, int ConfidencePercent);
}
