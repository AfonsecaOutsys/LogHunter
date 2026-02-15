using System.Globalization;
using System.Text;

namespace LogHunter.Services;

public static class AlbScanner
{
    public static List<string> GetLogFiles()
    {
        var albRoot = AppFolders.ALB;
        if (!Directory.Exists(albRoot)) return new List<string>();

        // You said: analyzing .log only
        return Directory.EnumerateFiles(albRoot, "*.log", SearchOption.AllDirectories).ToList();
    }

    // ------------------------
    // Fast field extractors
    // ------------------------
    // ALB token indices we rely on (0-based):
    //  1  = timestamp
    //  3  = client:port
    //  4  = target:port
    //  6  = target_processing_time
    // 12  = "request" (quoted)
    // 22  = "actions_executed" (quoted)
    //
    // NOTE: We use a tokenizer that treats quoted fields as single tokens.
    // This keeps behavior aligned with real ALB logs.

    public static string? ExtractAlbClientIp(string line)
    {
        if (!TryGetToken(line.AsSpan(), 3, out var client)) return null;

        int colon = client.IndexOf(':');
        if (colon <= 0) return client.Length > 0 ? client.ToString() : null;

        return client[..colon].ToString();
    }

    public static DateTime? ExtractAlbTimestampUtc(string line)
    {
        if (!TryGetToken(line.AsSpan(), 1, out var ts)) return null;

        // ALB timestamps are ISO-ish with Z. We force universal.
        if (DateTime.TryParse(ts, CultureInfo.InvariantCulture,
                DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out var dt))
            return DateTime.SpecifyKind(dt, DateTimeKind.Utc);

        return null;
    }

    public static string? ExtractAlbTargetHost(string line)
    {
        if (!TryGetToken(line.AsSpan(), 4, out var target)) return null;
        return target.Length > 0 ? target.ToString() : null;
    }

    public static double? ExtractAlbTargetProcessingTimeSeconds(string line)
    {
        if (!TryGetToken(line.AsSpan(), 6, out var dur)) return null;

        if (double.TryParse(dur, NumberStyles.Float, CultureInfo.InvariantCulture, out var v))
            return v;

        return null;
    }

    public static string? ExtractAlbActionsExecuted(string line)
    {
        if (!TryGetToken(line.AsSpan(), 22, out var actions)) return null;
        return actions.Length > 0 ? actions.ToString() : null;
    }

    public static string? ExtractAlbUriNoQuery(string line)
    {
        if (!TryGetToken(line.AsSpan(), 12, out var req)) return null;
        return ExtractUriNoQueryFromRequest(req);
    }

    // request example:
    // POST https://host:443/Enrollment/CheckStatus.aspx HTTP/1.1
    private static string ExtractUriNoQueryFromRequest(ReadOnlySpan<char> request)
    {
        if (request.Length == 0) return "";

        int sp1 = request.IndexOf(' ');
        if (sp1 < 0 || sp1 + 1 >= request.Length) return "";

        var rest = request[(sp1 + 1)..];
        int sp2 = rest.IndexOf(' ');
        ReadOnlySpan<char> url = sp2 >= 0 ? rest[..sp2] : rest;

        // strip query
        int q = url.IndexOf('?');
        if (q >= 0) url = url[..q];

        // absolute URL -> take path
        int scheme = url.IndexOf("://", StringComparison.Ordinal);
        if (scheme >= 0)
        {
            int afterScheme = scheme + 3;
            var after = url[afterScheme..];
            int slash = after.IndexOf('/');
            if (slash >= 0)
            {
                var path = url[(afterScheme + slash)..];
                return path.Length == 0 ? "/" : path.ToString();
            }
            return "/";
        }

        // already path-ish
        return url.ToString();
    }

    /// <summary>
    /// Tokenizer for ALB logs: space-delimited, but quoted segments count as one token.
    /// Returns token WITHOUT surrounding quotes.
    /// </summary>
    private static bool TryGetToken(ReadOnlySpan<char> line, int tokenIndex, out ReadOnlySpan<char> token)
    {
        token = default;

        int idx = 0;
        int current = 0;

        while (idx < line.Length)
        {
            while (idx < line.Length && line[idx] == ' ') idx++;
            if (idx >= line.Length) break;

            bool quoted = line[idx] == '"';
            int start = idx;

            if (quoted)
            {
                start++;
                idx = start;
                while (idx < line.Length && line[idx] != '"') idx++;
                int end = idx;
                idx = Math.Min(idx + 1, line.Length); // consume closing quote

                if (current == tokenIndex)
                {
                    token = line.Slice(start, end - start);
                    return true;
                }

                current++;
            }
            else
            {
                while (idx < line.Length && line[idx] != ' ') idx++;
                int end = idx;

                if (current == tokenIndex)
                {
                    token = line.Slice(start, end - start);
                    return true;
                }

                current++;
            }
        }

        return false;
    }

    // ------------------------
    // Optimized scanners (chunked progress + parse-on-demand)
    // ------------------------

    public static async Task ScanFileForOverallIpCountsAsync(
        string filePath,
        Dictionary<string, int> ipCounts,
        Action<long> reportBytesDelta)
    {
        using var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite, bufferSize: 1 << 20, FileOptions.SequentialScan);
        using var sr = new StreamReader(fs, Encoding.UTF8, detectEncodingFromByteOrderMarks: true, bufferSize: 1 << 20);

        long lastReportedPos = 0;
        const long chunk = 64L * 1024 * 1024; // 64MB

        while (true)
        {
            var line = await sr.ReadLineAsync().ConfigureAwait(false);
            if (line is null) break;
            if (line.Length == 0) continue;

            var ip = ExtractAlbClientIp(line);
            if (ip is null) continue;

            if (ipCounts.TryGetValue(ip, out var cur))
                ipCounts[ip] = cur + 1;
            else
                ipCounts[ip] = 1;

            var pos = fs.Position;
            if (pos - lastReportedPos >= chunk)
            {
                reportBytesDelta(pos - lastReportedPos);
                lastReportedPos = pos;
            }
        }

        var remaining = fs.Length - lastReportedPos;
        if (remaining > 0) reportBytesDelta(remaining);
    }

    public static async Task ScanFileForEndpointIpCountsAsync(
        string filePath,
        string endpointFragment,
        Dictionary<string, int> ipCounts,
        Action<long> reportBytesDelta)
    {
        using var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite, bufferSize: 1 << 20, FileOptions.SequentialScan);
        using var sr = new StreamReader(fs, Encoding.UTF8, detectEncodingFromByteOrderMarks: true, bufferSize: 1 << 20);

        long lastReportedPos = 0;
        const long chunk = 64L * 1024 * 1024; // 64MB

        while (true)
        {
            var line = await sr.ReadLineAsync().ConfigureAwait(false);
            if (line is null) break;
            if (line.Length == 0) continue;

            // Cheap filter first (saves CPU)
            if (line.IndexOf(endpointFragment, StringComparison.OrdinalIgnoreCase) < 0)
                continue;

            var ip = ExtractAlbClientIp(line);
            if (ip is null) continue;

            if (ipCounts.TryGetValue(ip, out var cur))
                ipCounts[ip] = cur + 1;
            else
                ipCounts[ip] = 1;

            var pos = fs.Position;
            if (pos - lastReportedPos >= chunk)
            {
                reportBytesDelta(pos - lastReportedPos);
                lastReportedPos = pos;
            }
        }

        var remaining = fs.Length - lastReportedPos;
        if (remaining > 0) reportBytesDelta(remaining);
    }

    public static async Task ScanFileForIpUriCountsAsync(
        string filePath,
        Dictionary<string, int> pairCounts,
        Action<long> reportBytesDelta)
    {
        using var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite, bufferSize: 1 << 20, FileOptions.SequentialScan);
        using var sr = new StreamReader(fs, Encoding.UTF8, detectEncodingFromByteOrderMarks: true, bufferSize: 1 << 20);

        long lastReportedPos = 0;
        const long chunk = 64L * 1024 * 1024; // 64MB

        while (true)
        {
            var line = await sr.ReadLineAsync().ConfigureAwait(false);
            if (line is null) break;
            if (line.Length == 0) continue;

            var ip = ExtractAlbClientIp(line);
            if (ip is null) continue;

            var uri = ExtractAlbUriNoQuery(line);
            if (string.IsNullOrEmpty(uri)) continue;

            // old format: "IP\tURI" to avoid heavy object keys
            var key = $"{ip}\t{uri}";

            if (pairCounts.TryGetValue(key, out var cur))
                pairCounts[key] = cur + 1;
            else
                pairCounts[key] = 1;

            var pos = fs.Position;
            if (pos - lastReportedPos >= chunk)
            {
                reportBytesDelta(pos - lastReportedPos);
                lastReportedPos = pos;
            }
        }

        var remaining = fs.Length - lastReportedPos;
        if (remaining > 0) reportBytesDelta(remaining);
    }
}
