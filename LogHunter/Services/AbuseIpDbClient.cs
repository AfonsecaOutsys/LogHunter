using System.Globalization;
using System.Net;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace LogHunter.Services;

public sealed class AbuseIpDbClient : IDisposable
{
    // Put your company key here (internal tool).
    // Users can override via /AbuseIP/config.json OR per-run prompt.
    private const string DefaultApiKey = "a1f11549914313f6db7572eafcacc897ed33c0473a1e9b67e1af0607b47a95f07589745d7e2a6034";

    private const string ConfigDirName = "AbuseIP";
    private const string ConfigFileName = "config.json";

    private static readonly Uri BaseUri = new("https://api.abuseipdb.com/");

    private readonly HttpClient _http;

    public string KeySource { get; }

    public AbuseIpDbClient(string workspaceRoot, string? apiKeyOverride = null)
    {
        var cfg = LoadConfig(workspaceRoot);

        string apiKey;
        if (!string.IsNullOrWhiteSpace(apiKeyOverride))
        {
            apiKey = apiKeyOverride.Trim();
            KeySource = "session override";
        }
        else if (!string.IsNullOrWhiteSpace(cfg.ApiKey))
        {
            apiKey = cfg.ApiKey!.Trim();
            KeySource = "config override";
        }
        else
        {
            apiKey = DefaultApiKey;
            KeySource = "hard-coded default";
        }

        _http = new HttpClient
        {
            BaseAddress = BaseUri,
            Timeout = TimeSpan.FromSeconds(Math.Clamp(cfg.TimeoutSeconds, 5, 120))
        };

        _http.DefaultRequestHeaders.Accept.Clear();
        _http.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));

        // AbuseIPDB expects header name "Key" for the API key.
        _http.DefaultRequestHeaders.Remove("Key");
        _http.DefaultRequestHeaders.Add("Key", apiKey);
    }

    public void Dispose() => _http.Dispose();

    public async Task<AbuseIpCheckResult> CheckAsync(string ipAddress, int maxAgeInDays, bool verbose, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(ipAddress))
            throw new ArgumentException("ipAddress is required.", nameof(ipAddress));

        maxAgeInDays = Math.Clamp(maxAgeInDays, 1, 365);

        var url = new StringBuilder();
        url.Append("api/v2/check?ipAddress=");
        url.Append(Uri.EscapeDataString(ipAddress.Trim()));
        url.Append("&maxAgeInDays=");
        url.Append(maxAgeInDays);

        if (verbose)
            url.Append("&verbose");

        // Small retry for transient 429s; daily quota should be handled by caller.
        for (var attempt = 1; attempt <= 3; attempt++)
        {
            using var req = new HttpRequestMessage(HttpMethod.Get, url.ToString());
            using var resp = await _http.SendAsync(req, HttpCompletionOption.ResponseHeadersRead, ct).ConfigureAwait(false);

            if (resp.StatusCode is HttpStatusCode.Unauthorized or HttpStatusCode.Forbidden)
            {
                var body = await resp.Content.ReadAsStringAsync(ct).ConfigureAwait(false);
                throw new AbuseIpAuthException($"Auth failed (HTTP {(int)resp.StatusCode}). {TrimForError(body)}");
            }

            if (resp.StatusCode == (HttpStatusCode)429)
            {
                var rl = ReadRateLimit(resp);

                // If remaining=0 => daily quota hit (don’t wait hours; let caller prompt for a new key)
                if (rl.Remaining == 0)
                    throw new AbuseIpQuotaExceededException(rl);

                // otherwise, transient backoff
                var delay = rl.RetryAfter ?? TimeSpan.FromSeconds(Math.Min(10, 1 << (attempt - 1))); // 1,2,4
                await Task.Delay(delay, ct).ConfigureAwait(false);
                continue;
            }

            var content = await resp.Content.ReadAsStringAsync(ct).ConfigureAwait(false);

            if (!resp.IsSuccessStatusCode)
                throw new InvalidOperationException($"HTTP {(int)resp.StatusCode} {resp.ReasonPhrase}: {TrimForError(content)}");

            var parsed = JsonSerializer.Deserialize<CheckResponse>(content, JsonOpts)
                         ?? throw new InvalidOperationException("Invalid JSON response.");

            if (parsed.Data is null)
                throw new InvalidOperationException("Response missing 'data'.");

            var d = parsed.Data;

            return new AbuseIpCheckResult(
                IpAddress: d.IpAddress ?? ipAddress,
                AbuseConfidenceScore: d.AbuseConfidenceScore,
                TotalReports: d.TotalReports,
                CountryCode: d.CountryCode,
                UsageType: d.UsageType,
                Isp: d.Isp,
                Domain: d.Domain,
                LastReportedAt: d.LastReportedAt);
        }

        throw new InvalidOperationException("Too many transient failures (retries exhausted).");
    }

    public static AbuseIpConfig LoadConfig(string workspaceRoot)
    {
        var path = GetConfigPath(workspaceRoot);

        try
        {
            if (!File.Exists(path))
                return AbuseIpConfig.Default;

            var json = File.ReadAllText(path);
            var cfg = JsonSerializer.Deserialize<AbuseIpConfig>(json, JsonOpts);

            return cfg ?? AbuseIpConfig.Default;
        }
        catch
        {
            return AbuseIpConfig.Default;
        }
    }

    public static void SaveConfig(string workspaceRoot, AbuseIpConfig cfg)
    {
        var dir = Path.Combine(workspaceRoot, ConfigDirName);
        Directory.CreateDirectory(dir);

        var path = Path.Combine(dir, ConfigFileName);

        var json = JsonSerializer.Serialize(cfg, new JsonSerializerOptions(JsonOpts)
        {
            WriteIndented = true
        });

        File.WriteAllText(path, json);
    }

    public static string GetConfigPath(string workspaceRoot)
        => Path.Combine(workspaceRoot, ConfigDirName, ConfigFileName);

    // ---------------------------
    // CSV export (now with ScoreBand)
    // ---------------------------
    public static void ExportResultsCsv(string path, IEnumerable<AbuseIpCheckResult> results)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);

        using var sw = new StreamWriter(path, false, new UTF8Encoding(encoderShouldEmitUTF8Identifier: false));

        sw.WriteLine("IpAddress,AbuseConfidenceScore,ScoreBand,TotalReports,CountryCode,UsageType,ISP,Domain,LastReportedAt");

        foreach (var r in results)
        {
            sw.WriteLine(string.Join(",",
                Csv(r.IpAddress),
                r.AbuseConfidenceScore.ToString(CultureInfo.InvariantCulture),
                Csv(ScoreBand(r.AbuseConfidenceScore)),
                r.TotalReports.ToString(CultureInfo.InvariantCulture),
                Csv(r.CountryCode),
                Csv(r.UsageType),
                Csv(r.Isp),
                Csv(r.Domain),
                Csv(r.LastReportedAt?.UtcDateTime.ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture) + "Z")
            ));
        }
    }

    private static string ScoreBand(int score)
    {
        if (score <= 0) return "Clean";
        if (score <= 25) return "Low";
        if (score <= 50) return "Medium";
        if (score <= 75) return "High";
        return "Critical";
    }

    private static string Csv(string? s)
    {
        if (string.IsNullOrEmpty(s))
            return "";

        var needsQuotes = s.Contains(',') || s.Contains('"') || s.Contains('\n') || s.Contains('\r');
        if (!needsQuotes) return s;

        return "\"" + s.Replace("\"", "\"\"") + "\"";
    }

    private static RateLimitInfo ReadRateLimit(HttpResponseMessage resp)
    {
        int? limit = TryGetIntHeader(resp.Headers, "X-RateLimit-Limit");
        int? remaining = TryGetIntHeader(resp.Headers, "X-RateLimit-Remaining");
        long? resetEpoch = TryGetLongHeader(resp.Headers, "X-RateLimit-Reset");

        DateTimeOffset? resetAtUtc = null;
        if (resetEpoch is { } e && e > 0)
            resetAtUtc = DateTimeOffset.FromUnixTimeSeconds(e);

        TimeSpan? retryAfter = resp.Headers.RetryAfter?.Delta;
        if (retryAfter is null && resp.Headers.RetryAfter?.Date is { } dt)
        {
            var delta = dt - DateTimeOffset.UtcNow;
            if (delta > TimeSpan.Zero) retryAfter = delta;
        }

        return new RateLimitInfo(limit, remaining, resetAtUtc, retryAfter);
    }

    private static int? TryGetIntHeader(HttpResponseHeaders headers, string name)
    {
        if (!headers.TryGetValues(name, out var vals))
            return null;

        var s = vals.FirstOrDefault();
        return int.TryParse(s, NumberStyles.Integer, CultureInfo.InvariantCulture, out var i) ? i : null;
    }

    private static long? TryGetLongHeader(HttpResponseHeaders headers, string name)
    {
        if (!headers.TryGetValues(name, out var vals))
            return null;

        var s = vals.FirstOrDefault();
        return long.TryParse(s, NumberStyles.Integer, CultureInfo.InvariantCulture, out var i) ? i : null;
    }

    private static string TrimForError(string s)
        => s.Length <= 500 ? s : s[..500] + "…";

    private static readonly JsonSerializerOptions JsonOpts = new()
    {
        PropertyNameCaseInsensitive = true
    };

    public sealed record AbuseIpConfig(
        [property: JsonPropertyName("apiKey")] string? ApiKey,
        [property: JsonPropertyName("maxAgeInDays")] int MaxAgeInDays,
        [property: JsonPropertyName("verbose")] bool Verbose,
        [property: JsonPropertyName("timeoutSeconds")] int TimeoutSeconds)
    {
        public static AbuseIpConfig Default => new(
            ApiKey: null,
            MaxAgeInDays: 30,
            Verbose: false,
            TimeoutSeconds: 30);
    }

    private sealed class CheckResponse
    {
        [JsonPropertyName("data")]
        public CheckData? Data { get; set; }
    }

    private sealed class CheckData
    {
        [JsonPropertyName("ipAddress")]
        public string? IpAddress { get; set; }

        [JsonPropertyName("abuseConfidenceScore")]
        public int AbuseConfidenceScore { get; set; }

        [JsonPropertyName("countryCode")]
        public string? CountryCode { get; set; }

        [JsonPropertyName("usageType")]
        public string? UsageType { get; set; }

        [JsonPropertyName("isp")]
        public string? Isp { get; set; }

        [JsonPropertyName("domain")]
        public string? Domain { get; set; }

        [JsonPropertyName("totalReports")]
        public int TotalReports { get; set; }

        [JsonPropertyName("lastReportedAt")]
        public DateTimeOffset? LastReportedAt { get; set; }
    }

    public sealed record RateLimitInfo(int? Limit, int? Remaining, DateTimeOffset? ResetAtUtc, TimeSpan? RetryAfter);
}

public sealed record AbuseIpCheckResult(
    string IpAddress,
    int AbuseConfidenceScore,
    int TotalReports,
    string? CountryCode,
    string? UsageType,
    string? Isp,
    string? Domain,
    DateTimeOffset? LastReportedAt);

public sealed class AbuseIpQuotaExceededException : Exception
{
    public AbuseIpDbClient.RateLimitInfo RateLimit { get; }

    public AbuseIpQuotaExceededException(AbuseIpDbClient.RateLimitInfo rateLimit)
        : base(BuildMessage(rateLimit))
    {
        RateLimit = rateLimit;
    }

    private static string BuildMessage(AbuseIpDbClient.RateLimitInfo rl)
    {
        var reset = rl.ResetAtUtc?.ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture) + "Z";
        return $"Daily quota exceeded (Remaining={rl.Remaining?.ToString() ?? "?"}, Limit={rl.Limit?.ToString() ?? "?"}, ResetAt={reset ?? "?"}).";
    }
}

public sealed class AbuseIpAuthException : Exception
{
    public AbuseIpAuthException(string message) : base(message) { }
}
