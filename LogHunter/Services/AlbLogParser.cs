using System;
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
    // 12: "request" (quoted)
    // 22: "actions_executed" (quoted)
    public static bool TryParse(string line, out AlbEntry entry)
    {
        entry = default;

        if (string.IsNullOrEmpty(line))
            return false;

        var s = line.AsSpan();

        // Get needed tokens as spans (quoted tokens are returned without surrounding quotes).
        if (!TryGetToken(s, 1, out var tsSpan)) return false;
        if (!TryGetToken(s, 3, out var clientSpan)) return false;
        if (!TryGetToken(s, 4, out var targetSpan)) return false;
        if (!TryGetToken(s, 6, out var tProcSpan)) return false;
        if (!TryGetToken(s, 12, out var reqSpan)) return false;
        if (!TryGetToken(s, 22, out var actionsSpan)) return false;

        // Timestamp (ALB uses ISO-ish with Z). Keep behavior strict.
        if (!DateTime.TryParse(tsSpan, CultureInfo.InvariantCulture, DateTimeStyles.AdjustToUniversal, out var ts))
            return false;

        // Client IP (strip :port)
        var clientIpSpan = clientSpan;
        int colon = clientIpSpan.IndexOf(':');
        if (colon > 0)
            clientIpSpan = clientIpSpan[..colon];

        if (clientIpSpan.Length == 0)
            return false;

        // target_processing_time seconds (non-fatal if unparsable)
        double targetProcSec = 0;
        _ = double.TryParse(tProcSpan, NumberStyles.Float, CultureInfo.InvariantCulture, out targetProcSec);

        // Request => extract URI (no query)
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
    /// Tokenizer that treats quoted segments as a single token.
    /// Returns the token content WITHOUT surrounding quotes. tokenIndex is 0-based.
    /// </summary>
    private static bool TryGetToken(ReadOnlySpan<char> line, int tokenIndex, out ReadOnlySpan<char> token)
    {
        token = default;

        int idx = 0;
        int current = 0;

        while (idx < line.Length)
        {
            while (idx < line.Length && line[idx] == ' ')
                idx++;

            if (idx >= line.Length)
                break;

            bool quoted = line[idx] == '"';
            int start = idx;

            if (quoted)
            {
                start++; // inside quote
                idx = start;

                while (idx < line.Length && line[idx] != '"')
                    idx++;

                int end = idx; // exclusive
                idx = Math.Min(idx + 1, line.Length); // consume closing quote (if present)

                if (current == tokenIndex)
                {
                    token = line.Slice(start, end - start);
                    return true;
                }

                current++;
                continue;
            }

            while (idx < line.Length && line[idx] != ' ')
                idx++;

            int endUnquoted = idx;

            if (current == tokenIndex)
            {
                token = line.Slice(start, endUnquoted - start);
                return true;
            }

            current++;
        }

        return false;
    }

    // request example:
    // POST https://portal.example.com:443/.../ActionLogin_Wrapper HTTP/1.1
    private static string ExtractUriNoQueryFromRequest(ReadOnlySpan<char> request)
    {
        // Keep "-" sentinel behavior (used in grouping/output).
        if (request.Length == 0)
            return "-";

        int sp1 = request.IndexOf(' ');
        if (sp1 < 0 || sp1 + 1 >= request.Length)
            return "-";

        var rest = request[(sp1 + 1)..];

        int sp2 = rest.IndexOf(' ');
        ReadOnlySpan<char> url = sp2 >= 0 ? rest[..sp2] : rest;

        // Strip query
        int q = url.IndexOf('?');
        if (q >= 0) url = url[..q];

        // If absolute URL, get path after host
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

        // Already a path
        return url.Length == 0 ? "-" : url.ToString();
    }

    /// <summary>
    /// Mirrors the original definition: "blocked" == NOT containing "waf,forward".
    /// </summary>
    public static bool IsWafBlockedByYourDefinition(string actionsExecuted)
    {
        if (string.IsNullOrEmpty(actionsExecuted))
            return true;

        return !actionsExecuted.Contains("waf,forward", StringComparison.OrdinalIgnoreCase);
    }
}