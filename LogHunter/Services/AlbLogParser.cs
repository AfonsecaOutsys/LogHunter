using System.Globalization;
using LogHunter.Models;

namespace LogHunter.Services;

public static class AlbLogParser
{
    // We rely on ALB log structure where:
    //  1: timestamp
    //  3: client:port
    //  4: target:port
    //  6: target_processing_time
    //  12: "request" (quoted)
    //  22: "actions_executed" (quoted)
    public static bool TryParse(string line, out AlbEntry entry)
    {
        entry = default;
        if (string.IsNullOrEmpty(line)) return false;

        var s = line.AsSpan();

        // Get needed tokens as spans (quotes removed by returning inner span)
        if (!TryGetToken(s, 1, out var tsSpan)) return false;
        if (!TryGetToken(s, 3, out var clientSpan)) return false;
        if (!TryGetToken(s, 4, out var targetSpan)) return false;
        if (!TryGetToken(s, 6, out var tProcSpan)) return false;
        if (!TryGetToken(s, 12, out var reqSpan)) return false;
        if (!TryGetToken(s, 22, out var actionsSpan)) return false;

        // timestamp
        if (!DateTime.TryParse(tsSpan, CultureInfo.InvariantCulture, DateTimeStyles.AdjustToUniversal, out var ts))
            return false;

        // client ip (strip :port)
        var clientIpSpan = clientSpan;
        int colon = clientIpSpan.IndexOf(':');
        if (colon > 0) clientIpSpan = clientIpSpan[..colon];
        if (clientIpSpan.Length == 0) return false;

        // target_processing_time seconds
        double targetProcSec = 0;
        _ = double.TryParse(tProcSpan, NumberStyles.Float, CultureInfo.InvariantCulture, out targetProcSec);

        // request => extract URL and then URI no query
        var uriNoQuery = ExtractUriNoQueryFromRequest(reqSpan);

        entry = new AlbEntry(
            TimestampUtc: DateTime.SpecifyKind(ts, DateTimeKind.Utc),
            ClientIp: clientIpSpan.ToString(),
            UriNoQuery: uriNoQuery,
            TargetHostPort: targetSpan.ToString(),
            TargetProcessingTimeSeconds: targetProcSec,
            ActionsExecuted: actionsSpan.ToString()
        );

        return true;
    }

    /// <summary>
    /// Tokenizer that understands quoted segments as single tokens.
    /// Returns the token content WITHOUT surrounding quotes.
    /// tokenIndex is 0-based.
    /// </summary>
    private static bool TryGetToken(ReadOnlySpan<char> line, int tokenIndex, out ReadOnlySpan<char> token)
    {
        token = default;

        int idx = 0;
        int current = 0;

        while (idx < line.Length)
        {
            // skip spaces
            while (idx < line.Length && line[idx] == ' ') idx++;
            if (idx >= line.Length) break;

            bool quoted = line[idx] == '"';
            int start = idx;

            if (quoted)
            {
                start++; // inside quote
                idx = start;
                while (idx < line.Length && line[idx] != '"') idx++;
                int end = idx; // exclusive
                idx = Math.Min(idx + 1, line.Length); // consume closing quote
                if (current == tokenIndex)
                {
                    token = line.Slice(start, end - start);
                    return true;
                }
                current++;
                continue;
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
                continue;
            }
        }

        return false;
    }

    // request span example:
    // POST https://portal.unionbankph.com:443/business/.../ActionLogin_Wrapper HTTP/1.1
    private static string ExtractUriNoQueryFromRequest(ReadOnlySpan<char> request)
    {
        if (request.Length == 0) return "-";

        // find first space (after method)
        int sp1 = request.IndexOf(' ');
        if (sp1 < 0 || sp1 + 1 >= request.Length) return "-";

        var rest = request[(sp1 + 1)..];

        // find second space (before HTTP/1.1)
        int sp2 = rest.IndexOf(' ');
        ReadOnlySpan<char> url = sp2 >= 0 ? rest[..sp2] : rest;

        // strip query
        int q = url.IndexOf('?');
        if (q >= 0) url = url[..q];

        // if absolute URL, get path after host
        int scheme = url.IndexOf("://", StringComparison.Ordinal);
        if (scheme >= 0)
        {
            int afterScheme = scheme + 3;
            int slash = url[afterScheme..].IndexOf('/');
            if (slash >= 0)
            {
                var path = url[(afterScheme + slash)..];
                return path.Length == 0 ? "/" : path.ToString();
            }
            return "/";
        }

        // already a path
        return url.Length == 0 ? "-" : url.ToString();
    }

    /// <summary>
    /// Mirrors your shell logic: grep -v "waf,forward"
    /// </summary>
    public static bool IsWafBlockedByYourDefinition(string actionsExecuted)
    {
        if (string.IsNullOrEmpty(actionsExecuted)) return true;
        return !actionsExecuted.Contains("waf,forward", StringComparison.OrdinalIgnoreCase);
    }
}
