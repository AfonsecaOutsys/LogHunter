using LogHunter.Models;
using LogHunter.Utils;
using Spectre.Console;
using System.Net;

namespace LogHunter.Services;

public static class IisOption_4xxPivot2xx3xx
{
    private const string SelectAllSentinel = "__ALL__";

    /// <summary>
    /// Flow:
    ///  Pass 1: scan IIS logs for 4xx per (real) IP -> show Top 15 with per-status breakdown.
    ///  Pick suspicious IPs -> Pass 2: export all 2xx/3xx lines for those IPs to a W3C .log + show pivot summary.
    ///
    /// Input folder:  {root}\IIS
    /// Output folder: {root}\output
    /// </summary>
    public static async Task RunAsync(string root, CancellationToken ct = default)
    {
        ConsoleEx.Header("IIS: 4xx → pick suspicious IPs → pivot to 2xx/3xx");

        var iisDir = Path.Combine(root, "IIS");
        if (!Directory.Exists(iisDir))
        {
            AnsiConsole.MarkupLine($"[red]Missing IIS folder:[/] {Markup.Escape(iisDir)}");
            ConsoleEx.Pause();
            return;
        }

        var files = IisW3cReader.EnumerateLogFiles(iisDir);
        if (files.Count == 0)
        {
            AnsiConsole.MarkupLine($"[yellow]No IIS logs found[/] under: {Markup.Escape(iisDir)}");
            ConsoleEx.Pause();
            return;
        }

        // ---------- Pass 1: 4xx stats ----------
        var statsByIp = new Dictionary<string, IisFourxxStats>(StringComparer.OrdinalIgnoreCase);
        IisW3cReader.FieldMap? firstMap = null;

        // Noise filters
        var ignoreUAPrefixes = new[]
        {
            "ELB-HealthChecker/",
        };

        await AnsiConsole.Status()
            .Spinner(Spinner.Known.Dots)
            .StartAsync("Pass 1/2: scanning 4xx…", async ctx =>
            {
                for (var f = 0; f < files.Count; f++)
                {
                    ct.ThrowIfCancellationRequested();

                    var file = files[f];
                    ctx.Status($"Pass 1/2: scanning 4xx… ({f + 1}/{files.Count}) {Path.GetFileName(file)}");

                    var map = await IisW3cReader.ReadFieldMapAsync(file, ct);
                    if (map is null)
                        continue;

                    firstMap ??= map;

                    if (!map.TryGetIndex("sc-status", out var iStatus))
                        continue;

                    map.TryGetIndex("OriginalIP", out var iOriginalIp);
                    map.TryGetIndex("c-ip", out var iCIp);
                    map.TryGetIndex("cs(User-Agent)", out var iUA);

                    await IisW3cReader.ForEachDataLineAsync(file, ct, (rawLine, tokens) =>
                    {
                        if (!TryParseInt(tokens.Get(iStatus), out var status))
                            return;

                        if (status < 400 || status > 499)
                            return;

                        // Ignore ELB health checker noise
                        if (iUA >= 0)
                        {
                            var ua = tokens.Get(iUA);
                            if (!ua.IsEmpty && ua[0] != '-')
                            {
                                var uaStr = ua.ToString();
                                for (int k = 0; k < ignoreUAPrefixes.Length; k++)
                                {
                                    if (uaStr.StartsWith(ignoreUAPrefixes[k], StringComparison.OrdinalIgnoreCase))
                                        return;
                                }
                            }
                        }

                        var ip = GetRealIpPreferOriginal(tokens, iOriginalIp, iCIp);
                        if (ip is null)
                            return;

                        // Default: exclude private/loopback to focus on real clients
                        if (IsPrivateOrLoopback(ip))
                            return;

                        if (!statsByIp.TryGetValue(ip, out var s))
                        {
                            s = new IisFourxxStats(ip);
                            statsByIp[ip] = s;
                        }

                        s.Add(status);
                    });
                }
            });

        if (statsByIp.Count == 0)
        {
            AnsiConsole.MarkupLine("[grey]No public-client 4xx traffic found (after filters).[/]");
            ConsoleEx.Pause();
            return;
        }

        var top = statsByIp.Values
            .OrderByDescending(s => s.Total4xx)
            .ThenBy(s => s.Ip, StringComparer.OrdinalIgnoreCase)
            .Take(15)
            .ToList();

        // ---------- Display Top 15 ----------
        ConsoleEx.Header("IIS: Top 4xx IPs", $"Workspace: {root}");

        for (int rank = 0; rank < top.Count; rank++)
        {
            var s = top[rank];
            AnsiConsole.MarkupLine($"[bold]Rank {rank + 1}[/] IP: [yellow]{Markup.Escape(s.Ip)}[/]  [dim]4xx:[/] [bold]{s.Total4xx:n0}[/] hits");

            foreach (var kv in s.StatusCounts.OrderBy(k => k.Key))
                AnsiConsole.MarkupLine($"  [dim]{kv.Key}:[/] {kv.Value:n0} hits");

            AnsiConsole.WriteLine();
        }

        // ---------- Pick suspicious IPs ----------
        var pick = new MultiSelectionPrompt<IpPick>()
            .Title("Select IP(s) to mark as suspicious (pivot to 2xx/3xx)")
            .NotRequired()
            .PageSize(16)
            .InstructionsText("[grey](Space to toggle, Enter to confirm)[/]")
            .UseConverter(p => p.Display);

        // "Select ALL" pseudo-choice (we interpret it after the prompt)
        pick.AddChoice(new IpPick(
            SelectAllSentinel,
            "[bold][[Select ALL]][/] Select all IPs shown above (Top 15)"
        ));

        foreach (var s in top)
            pick.AddChoice(new IpPick(s.Ip, MakePickLabel(s)));

        var selected = AnsiConsole.Prompt(pick);
        if (selected.Count == 0)
        {
            AnsiConsole.MarkupLine("[grey](no IPs selected)[/]");
            ConsoleEx.Pause();
            return;
        }

        HashSet<string> selectedIps;
        if (selected.Any(x => x.Ip == SelectAllSentinel))
            selectedIps = top.Select(x => x.Ip).ToHashSet(StringComparer.OrdinalIgnoreCase);
        else
            selectedIps = selected.Select(x => x.Ip).ToHashSet(StringComparer.OrdinalIgnoreCase);

        // ---------- Pass 2: export 2xx/3xx lines + pivot summaries ----------
        var outDir = Path.Combine(root, "output");
        Directory.CreateDirectory(outDir);

        var outFile = Path.Combine(outDir, $"iis_pivot_2xx3xx_{DateTime.UtcNow:yyyyMMdd_HHmmss}.log");

        var pivot = new Dictionary<string, IisPivotResult>(StringComparer.OrdinalIgnoreCase);
        foreach (var ip in selectedIps)
            pivot[ip] = new IisPivotResult(ip) { OutputFilePath = outFile };

        long exportedLines = 0;

        await using var outStream = File.Create(outFile);
        await using var outWriter = new StreamWriter(outStream);

        // Write header once (W3C format)
        if (firstMap is not null)
        {
            foreach (var h in firstMap.HeaderLines)
                await outWriter.WriteLineAsync(h);

            await outWriter.WriteLineAsync(firstMap.FieldsLine);
        }
        else
        {
            // Fallback minimal header (should be rare)
            await outWriter.WriteLineAsync("#Software: Microsoft Internet Information Services 10.0");
            await outWriter.WriteLineAsync("#Version: 1.0");
            await outWriter.WriteLineAsync($"#Date: {DateTime.UtcNow:yyyy-MM-dd HH:mm:ss}");
        }

        await AnsiConsole.Status()
            .Spinner(Spinner.Known.Dots)
            .StartAsync("Pass 2/2: exporting 2xx/3xx for selected IPs…", async ctx =>
            {
                for (var f = 0; f < files.Count; f++)
                {
                    ct.ThrowIfCancellationRequested();

                    var file = files[f];
                    ctx.Status($"Pass 2/2: exporting 2xx/3xx… ({f + 1}/{files.Count}) {Path.GetFileName(file)}");

                    var map = await IisW3cReader.ReadFieldMapAsync(file, ct);
                    if (map is null)
                        continue;

                    if (!map.TryGetIndex("sc-status", out var iStatus))
                        continue;

                    map.TryGetIndex("OriginalIP", out var iOriginalIp);
                    map.TryGetIndex("c-ip", out var iCIp);
                    map.TryGetIndex("cs-uri-stem", out var iUriStem);

                    await IisW3cReader.ForEachDataLineAsync(file, ct, (rawLine, tokens) =>
                    {
                        if (!TryParseInt(tokens.Get(iStatus), out var status))
                            return;

                        if (status < 200 || status > 399)
                            return;

                        var ip = GetRealIpPreferOriginal(tokens, iOriginalIp, iCIp);
                        if (ip is null)
                            return;

                        if (IsPrivateOrLoopback(ip))
                            return;

                        if (!selectedIps.Contains(ip))
                            return;

                        // export raw line
                        outWriter.WriteLine(rawLine);
                        exportedLines++;

                        // update pivot stats
                        var res = pivot[ip];
                        res.Add(status);

                        if (iUriStem >= 0)
                        {
                            var uri = tokens.Get(iUriStem);
                            if (!uri.IsEmpty && uri[0] != '-')
                                res.AddUri(uri.ToString());
                        }
                    });
                }
            });

        await outWriter.FlushAsync();

        // ---------- Show pivot summary ----------
        ConsoleEx.Header("IIS: Pivot results (2xx/3xx)");

        AnsiConsole.MarkupLine($"[dim]Selected IPs:[/] {selectedIps.Count}");
        AnsiConsole.MarkupLine($"[dim]Exported lines:[/] {exportedLines:n0}");
        AnsiConsole.MarkupLine($"[dim]Output:[/] {Markup.Escape(outFile)}");
        AnsiConsole.WriteLine();

        foreach (var ip in selectedIps.OrderBy(x => x, StringComparer.OrdinalIgnoreCase))
        {
            var r = pivot[ip];

            AnsiConsole.MarkupLine($"[bold]{Markup.Escape(ip)}[/]  [dim]2xx:[/] {r.Total2xx:n0}  [dim]3xx:[/] {r.Total3xx:n0}");

            foreach (var kv in r.StatusCounts.OrderBy(k => k.Key))
                AnsiConsole.MarkupLine($"  [dim]{kv.Key}:[/] {kv.Value:n0}");

            var topUris = r.TopUris(10);
            if (topUris.Count > 0)
            {
                AnsiConsole.MarkupLine("  [dim]Top URIs (2xx/3xx):[/]");
                foreach (var (uri, count) in topUris)
                {
                    var sensitive = LooksSensitiveOutSystems(uri);
                    var uriMarkup = sensitive ? $"[red]{Markup.Escape(uri)}[/]" : Markup.Escape(uri);
                    AnsiConsole.MarkupLine($"    {uriMarkup}  [dim]({count:n0})[/]");
                }
            }

            AnsiConsole.WriteLine();
        }

        ConsoleEx.Pause();
    }

    // -------------------- Helpers --------------------

    private sealed record IpPick(string Ip, string Display);

    private static string MakePickLabel(IisFourxxStats s)
    {
        var parts = new List<string>();

        if (s.StatusCounts.TryGetValue(404, out var c404) && c404 > 0) parts.Add($"404:{c404:n0}");
        if (s.StatusCounts.TryGetValue(403, out var c403) && c403 > 0) parts.Add($"403:{c403:n0}");
        if (s.StatusCounts.TryGetValue(401, out var c401) && c401 > 0) parts.Add($"401:{c401:n0}");
        if (s.StatusCounts.TryGetValue(400, out var c400) && c400 > 0) parts.Add($"400:{c400:n0}");

        var tail = parts.Count > 0 ? $" ({string.Join(", ", parts)})" : "";
        return $"{s.Ip} | 4xx:{s.Total4xx:n0}{tail}";
    }

    private static bool TryParseInt(ReadOnlySpan<char> s, out int value)
    {
        value = 0;
        if (s.IsEmpty || s[0] == '-') return false;
        return int.TryParse(s, out value);
    }

    private static string? GetRealIpPreferOriginal(IisW3cReader.TokenReader tokens, int iOriginalIp, int iCIp)
    {
        ReadOnlySpan<char> raw = default;

        if (iOriginalIp >= 0)
            raw = tokens.Get(iOriginalIp);

        if (raw.IsEmpty || raw[0] == '-')
        {
            if (iCIp >= 0)
                raw = tokens.Get(iCIp);
        }

        return NormalizeIp(raw);
    }

    private static string? NormalizeIp(ReadOnlySpan<char> raw)
    {
        if (raw.IsEmpty) return null;

        raw = raw.Trim();
        if (raw.IsEmpty || raw[0] == '-') return null;

        // "1.2.3.4, 10.0.0.1"
        var comma = raw.IndexOf(',');
        if (comma >= 0)
            raw = raw.Slice(0, comma).Trim();

        // "[::1]:1234" => "::1"
        if (raw.Length > 0 && raw[0] == '[')
        {
            var end = raw.IndexOf(']');
            if (end > 1)
                raw = raw.Slice(1, end - 1);
        }
        else
        {
            // IPv4:port (single colon)
            var colon = raw.IndexOf(':');
            if (colon > 0 && raw.Slice(colon + 1).IndexOf(':') < 0)
                raw = raw.Slice(0, colon);
        }

        var s = raw.ToString().Trim();
        return s.Length == 0 ? null : s;
    }

    private static bool IsPrivateOrLoopback(string ip)
    {
        if (!IPAddress.TryParse(ip, out var addr))
            return false;

        if (IPAddress.IsLoopback(addr))
            return true;

        if (addr.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
        {
            var b = addr.GetAddressBytes();
            if (b[0] == 10) return true;
            if (b[0] == 172 && b[1] >= 16 && b[1] <= 31) return true;
            if (b[0] == 192 && b[1] == 168) return true;
            if (b[0] == 169 && b[1] == 254) return true;
        }

        return false;
    }

    private static bool LooksSensitiveOutSystems(string uriStem)
    {
        if (uriStem.StartsWith("/ServiceCenter", StringComparison.OrdinalIgnoreCase)) return true;
        if (uriStem.StartsWith("/LifeTime", StringComparison.OrdinalIgnoreCase)) return true;
        if (uriStem.Contains("PlatformServices", StringComparison.OrdinalIgnoreCase)) return true;
        if (uriStem.Contains("/moduleservices", StringComparison.OrdinalIgnoreCase)) return true;
        if (uriStem.Contains("/rest/", StringComparison.OrdinalIgnoreCase)) return true;
        if (uriStem.Contains("/soap/", StringComparison.OrdinalIgnoreCase)) return true;
        if (uriStem.Contains(".asmx", StringComparison.OrdinalIgnoreCase)) return true;
        if (uriStem.StartsWith("/server.", StringComparison.OrdinalIgnoreCase)) return true;
        return false;
    }
}
