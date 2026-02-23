// Services/PlatformScanner.cs
using ExcelDataReader;
using Microsoft.VisualBasic.FileIO;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using IOSearchOption = System.IO.SearchOption;

namespace LogHunter.Services;

public static class PlatformScanner
{
    private static readonly Regex RxMissingFile = new(
        @"The file\s+.+\s+does not exist\.",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly Regex RxClientIp = new(
        @"ClientIp:\s*(?<ip>[0-9a-fA-F\.:]+)",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly Regex RxXff = new(
        @"X-Forwarded-For:\s*(?<ip>[0-9a-fA-F\.:, ]+)",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private const string DangerousPathNeedle =
        "A potentially dangerous Request.Path value was detected from the client";

    public static Task<PlatformSuspiciousScanResult> ScanSuspiciousRequestsAsync(
        string platformLogsDir,
        CancellationToken ct = default)
        => Task.Run(() => Scan(platformLogsDir, ct), ct);

    private static PlatformSuspiciousScanResult Scan(string dir, CancellationToken ct)
    {
        // ExcelDataReader sometimes needs this (esp. .xls); harmless for .xlsx
        Encoding.RegisterProvider(CodePagesEncodingProvider.Instance);

        var files = Directory.EnumerateFiles(dir, "*.*", IOSearchOption.AllDirectories)
            .Where(p => p.EndsWith(".csv", StringComparison.OrdinalIgnoreCase) ||
                        p.EndsWith(".xlsx", StringComparison.OrdinalIgnoreCase))
            .ToList();

        var res = new PlatformSuspiciousScanResult
        {
            FilesScanned = files.Count
        };

        foreach (var file in files)
        {
            ct.ThrowIfCancellationRequested();

            try
            {
                bool matchedThisFile = file.EndsWith(".csv", StringComparison.OrdinalIgnoreCase)
                    ? ScanCsv(file, res, ct)
                    : ScanXlsx(file, res, ct);

                if (matchedThisFile)
                    res.FilesMatched++;
            }
            catch
            {
                // Skip unreadable/broken files silently (logs are messy).
            }
        }

        res.FinalizeAggregates();
        return res;
    }

    private static bool ScanCsv(string path, PlatformSuspiciousScanResult res, CancellationToken ct)
    {
        // Detect delimiter quickly from header line
        var firstLine = File.ReadLines(path).FirstOrDefault() ?? "";
        var comma = firstLine.Count(c => c == ',');
        var semi = firstLine.Count(c => c == ';');
        var tab = firstLine.Count(c => c == '\t');

        var delimiter =
            tab > comma && tab > semi ? "\t" :
            semi > comma ? ";" : ",";

        using var parser = new TextFieldParser(path)
        {
            TextFieldType = FieldType.Delimited,
            HasFieldsEnclosedInQuotes = true,
            TrimWhiteSpace = false
        };
        parser.SetDelimiters(delimiter);

        var header = parser.ReadFields();
        if (header is null || header.Length == 0)
            return false;

        if (!TryResolveColumns(header, out var messageIdx, out var envIdx))
            return false;

        bool anyMatch = false;

        while (!parser.EndOfData)
        {
            ct.ThrowIfCancellationRequested();

            string[]? fields;
            try { fields = parser.ReadFields(); }
            catch { continue; }

            if (fields is null || fields.Length == 0)
                continue;

            if (messageIdx >= fields.Length || envIdx >= fields.Length)
                continue;

            var msg = fields[messageIdx] ?? "";
            var type = MatchSuspiciousType(msg);
            if (type is null)
                continue;

            var env = fields[envIdx] ?? "";
            if (!TryExtractEffectiveIp(env, out var effectiveIp, out var clientIp, out var xffIp))
                continue;

            anyMatch = true;
            res.AddHit(type.Value, effectiveIp!, clientIp, xffIp);
        }

        return anyMatch;
    }

    private static bool ScanXlsx(string path, PlatformSuspiciousScanResult res, CancellationToken ct)
    {
        using var stream = File.Open(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
        using var reader = ExcelReaderFactory.CreateReader(stream);

        bool anyMatch = false;

        do
        {
            ct.ThrowIfCancellationRequested();

            if (!reader.Read())
                continue;

            var headers = new string[reader.FieldCount];
            for (int i = 0; i < reader.FieldCount; i++)
                headers[i] = reader.GetValue(i)?.ToString() ?? "";

            if (!TryResolveColumns(headers, out var messageIdx, out var envIdx))
                continue;

            // Read rows
            while (reader.Read())
            {
                ct.ThrowIfCancellationRequested();

                var msg = reader.GetValue(messageIdx)?.ToString() ?? "";
                var type = MatchSuspiciousType(msg);
                if (type is null)
                    continue;

                var env = reader.GetValue(envIdx)?.ToString() ?? "";
                if (!TryExtractEffectiveIp(env, out var effectiveIp, out var clientIp, out var xffIp))
                    continue;

                anyMatch = true;
                res.AddHit(type.Value, effectiveIp!, clientIp, xffIp);
            }

        } while (reader.NextResult());

        return anyMatch;
    }

    private static PlatformSuspiciousType? MatchSuspiciousType(string msg)
    {
        if (msg.IndexOf(DangerousPathNeedle, StringComparison.OrdinalIgnoreCase) >= 0)
            return PlatformSuspiciousType.DangerousRequestPath;

        if (RxMissingFile.IsMatch(msg))
            return PlatformSuspiciousType.MissingFileDoesNotExist;

        return null;
    }

    private static bool TryResolveColumns(IReadOnlyList<string> headers, out int messageIdx, out int envIdx)
    {
        messageIdx = -1;
        envIdx = -1;

        for (int i = 0; i < headers.Count; i++)
        {
            var n = Norm(headers[i]);

            // Message candidates
            if (messageIdx < 0 && (n == "message" || n == "logbody"))
                messageIdx = i;

            // Environment info candidates (supports: environmentinformation, ...environment_information, ...environmentinformation)
            if (envIdx < 0 && n.EndsWith("environmentinformation", StringComparison.OrdinalIgnoreCase))
                envIdx = i;
        }

        return messageIdx >= 0 && envIdx >= 0;
    }

    private static bool TryExtractEffectiveIp(string env, out string? effectiveIp, out string? clientIp, out string? xffIp)
    {
        effectiveIp = null;
        clientIp = null;
        xffIp = null;

        if (string.IsNullOrWhiteSpace(env))
            return false;

        var mClient = RxClientIp.Match(env);
        if (mClient.Success)
            clientIp = mClient.Groups["ip"].Value.Trim();

        var mXff = RxXff.Match(env);
        if (mXff.Success)
        {
            var raw = mXff.Groups["ip"].Value.Trim();
            // Take first IP if multiple (comma-separated)
            xffIp = raw.Split(',')[0].Trim();
        }

        effectiveIp = !string.IsNullOrWhiteSpace(xffIp) ? xffIp : clientIp;
        return !string.IsNullOrWhiteSpace(effectiveIp);
    }

    private static string Norm(string s)
    {
        if (string.IsNullOrWhiteSpace(s))
            return "";

        // Lowercase + keep only letters/digits (so '.' '_' '-' etc don’t matter)
        Span<char> buffer = stackalloc char[s.Length];
        int p = 0;

        foreach (var ch in s)
        {
            if (char.IsLetterOrDigit(ch))
                buffer[p++] = char.ToLowerInvariant(ch);
        }

        return new string(buffer[..p]);
    }
}

public enum PlatformSuspiciousType
{
    DangerousRequestPath,
    MissingFileDoesNotExist
}

public sealed class PlatformSuspiciousScanResult
{
    public int FilesScanned { get; set; }
    public int FilesMatched { get; set; }
    public int MatchedRows { get; private set; }
    public int RowsWithXff { get; private set; }
    public int RowsWithoutXff { get; private set; }

    public int DistinctEffectiveIps { get; private set; }

    // Error type -> (Effective IP -> hits)
    public Dictionary<string, Dictionary<string, int>> EffectiveIpCountsByErrorType { get; } = new(StringComparer.OrdinalIgnoreCase);

    // For screen summaries
    public Dictionary<string, (int Rows, int DistinctEffectiveIps)> ByErrorType { get; } = new(StringComparer.OrdinalIgnoreCase);

    public List<(string Ip, int Hits)> TopEffectiveIpsOverall { get; private set; } = new();
    public Dictionary<string, List<(string Ip, int Hits)>> TopEffectiveIpsByErrorType { get; } = new(StringComparer.OrdinalIgnoreCase);

    public void AddHit(PlatformSuspiciousType type, string effectiveIp, string? clientIp, string? xffIp)
    {
        MatchedRows++;

        if (!string.IsNullOrWhiteSpace(xffIp))
            RowsWithXff++;
        else
            RowsWithoutXff++;

        var typeName = type switch
        {
            PlatformSuspiciousType.DangerousRequestPath => "Dangerous Request.Path",
            PlatformSuspiciousType.MissingFileDoesNotExist => "The file * does not exist",
            _ => type.ToString()
        };

        if (!EffectiveIpCountsByErrorType.TryGetValue(typeName, out var map))
        {
            map = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
            EffectiveIpCountsByErrorType[typeName] = map;
        }

        map.TryGetValue(effectiveIp, out var hits);
        map[effectiveIp] = hits + 1;
    }

    public void FinalizeAggregates()
    {
        var all = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);

        foreach (var (type, map) in EffectiveIpCountsByErrorType)
        {
            var rows = map.Values.Sum();
            var distinct = map.Count;

            ByErrorType[type] = (rows, distinct);

            var top = map
                .OrderByDescending(kvp => kvp.Value)
                .ThenBy(kvp => kvp.Key, StringComparer.OrdinalIgnoreCase)
                .Select(kvp => (kvp.Key, kvp.Value))
                .ToList();

            TopEffectiveIpsByErrorType[type] = top;

            foreach (var kvp in map)
            {
                all.TryGetValue(kvp.Key, out var hits);
                all[kvp.Key] = hits + kvp.Value;
            }
        }

        DistinctEffectiveIps = all.Count;

        TopEffectiveIpsOverall = all
            .OrderByDescending(kvp => kvp.Value)
            .ThenBy(kvp => kvp.Key, StringComparer.OrdinalIgnoreCase)
            .Select(kvp => (kvp.Key, kvp.Value))
            .ToList();
    }
}