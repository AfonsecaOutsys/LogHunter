using System.IO.Compression;
using System.Text;

namespace LogHunter.Utils;

/// <summary>
/// Minimal W3C (IIS) log reader:
/// - reads #Fields mapping per file
/// - iterates data lines
/// - provides TokenReader for fast token access (no Split allocations)
/// - supports .log and .log.gz
/// </summary>
public static class IisW3cReader
{
    public sealed class FieldMap
    {
        public required string FieldsLine { get; init; }
        public required List<string> HeaderLines { get; init; }
        public required Dictionary<string, int> Index { get; init; }

        public bool TryGetIndex(string field, out int index)
        {
            if (Index.TryGetValue(field, out index))
                return true;

            index = -1;
            return false;
        }
    }

    /// <summary>
    /// Token accessor for a single log line (space-delimited W3C tokens).
    /// Safe to pass around (stores the string line internally).
    /// </summary>
    public readonly struct TokenReader
    {
        private readonly string _line;

        public TokenReader(string line) => _line = line;

        public ReadOnlySpan<char> Get(int targetIndex)
        {
            if (targetIndex < 0)
                return ReadOnlySpan<char>.Empty;

            int idx = 0;
            int i = 0;

            while (i < _line.Length)
            {
                while (i < _line.Length && _line[i] == ' ') i++;
                if (i >= _line.Length) break;

                int start = i;
                while (i < _line.Length && _line[i] != ' ') i++;

                if (idx == targetIndex)
                    return _line.AsSpan(start, i - start);

                idx++;
            }

            return ReadOnlySpan<char>.Empty;
        }
    }

    public static List<string> EnumerateLogFiles(string rootDir)
    {
        var list = new List<string>();

        list.AddRange(Directory.EnumerateFiles(rootDir, "*.log", SearchOption.AllDirectories));
        list.AddRange(Directory.EnumerateFiles(rootDir, "*.log.gz", SearchOption.AllDirectories));

        list.Sort(StringComparer.OrdinalIgnoreCase);
        return list;
    }

    public static async Task<FieldMap?> ReadFieldMapAsync(string filePath, CancellationToken ct = default)
    {
        await using var stream = OpenPossiblyGz(filePath);
        using var reader = new StreamReader(stream, Encoding.UTF8, detectEncodingFromByteOrderMarks: true, bufferSize: 1 << 20);

        var header = new List<string>();
        string? fieldsLine = null;
        Dictionary<string, int>? idx = null;

        while (true)
        {
            ct.ThrowIfCancellationRequested();

            var line = await reader.ReadLineAsync();
            if (line is null) break;

            if (!line.StartsWith("#", StringComparison.Ordinal))
                break;

            if (line.StartsWith("#Fields:", StringComparison.OrdinalIgnoreCase))
            {
                fieldsLine = line;

                var fields = line.Substring("#Fields:".Length)
                    .Trim()
                    .Split(' ', StringSplitOptions.RemoveEmptyEntries);

                idx = new Dictionary<string, int>(fields.Length, StringComparer.OrdinalIgnoreCase);
                for (int i = 0; i < fields.Length; i++)
                    idx[fields[i]] = i;

                continue; // keep fields line separate; write it once on export
            }

            header.Add(line);
        }

        if (fieldsLine is null || idx is null)
            return null;

        // keep output W3C-ish if headers are missing
        if (header.Count == 0)
        {
            header.Add("#Software: Microsoft Internet Information Services 10.0");
            header.Add("#Version: 1.0");
            header.Add($"#Date: {DateTime.UtcNow:yyyy-MM-dd HH:mm:ss}");
        }

        return new FieldMap
        {
            FieldsLine = fieldsLine,
            HeaderLines = header,
            Index = idx
        };
    }

    /// <summary>
    /// Iterates each data line (non-header) and provides:
    /// - rawLine: original line (good for export)
    /// - tokens: TokenReader for fast token access
    /// </summary>
    public static async Task ForEachDataLineAsync(
        string filePath,
        CancellationToken ct,
        Action<string, TokenReader> onLine)
    {
        await using var stream = OpenPossiblyGz(filePath);
        using var reader = new StreamReader(stream, Encoding.UTF8, detectEncodingFromByteOrderMarks: true, bufferSize: 1 << 20);

        string? line;
        while ((line = await reader.ReadLineAsync()) is not null)
        {
            ct.ThrowIfCancellationRequested();

            if (line.Length == 0) continue;
            if (line[0] == '#') continue;

            onLine(line, new TokenReader(line));
        }
    }

    private static Stream OpenPossiblyGz(string filePath)
    {
        var fs = File.OpenRead(filePath);
        if (filePath.EndsWith(".gz", StringComparison.OrdinalIgnoreCase))
            return new GZipStream(fs, CompressionMode.Decompress);

        return fs;
    }
}
