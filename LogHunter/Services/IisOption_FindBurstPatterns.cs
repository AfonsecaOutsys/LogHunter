using LogHunter.Utils;
using Spectre.Console;
using System.Globalization;
using System.Net;

namespace LogHunter.Services;

public static class IisOption_FindBurstPatterns
{
    private const string SelectAllSentinel = "__ALL__";

    private sealed class BurstAgg
    {
        public required string Ip { get; init; }
        public required DateTime StartUtc { get; init; }
        public int BucketSeconds { get; init; }

        public int TotalDynamic { get; set; }
        public int TotalAll { get; set; }

        public int C2xx { get; set; }
        public int C3xx { get; set; }
        public int C4xx { get; set; }
        public int C5xx { get; set; }

        public int Get { get; set; }
        public int Post { get; set; }
        public int Head { get; set; }

        public long TimeTakenTotalMs { get; set; }
        public int TimeTakenMaxMs { get; set; }

        public string? Ua { get; set; }
        public bool UaMixed { get; set; }

        public int UniqueDynamicUris { get; set; }
        private HashSet<string>? _uniqueDyn;
        private readonly int _uniqueCap;

        private Dictionary<string, int>? _uriCounts;
        private readonly int _uriCap;

        public BurstAgg(int uniqueCap, int uriCap)
        {
            _uniqueCap = uniqueCap;
            _uriCap = uriCap;
        }

        public void AddDynamicUri(string uriStem)
        {
            if (UniqueDynamicUris < _uniqueCap)
            {
                _uniqueDyn ??= new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                if (_uniqueDyn.Add(uriStem))
                    UniqueDynamicUris++;
            }
            else
            {
                UniqueDynamicUris = _uniqueCap;
            }

            _uriCounts ??= new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
            if (_uriCounts.Count <= _uriCap)
            {
                if (_uriCounts.TryGetValue(uriStem, out var v)) _uriCounts[uriStem] = v + 1;
                else _uriCounts[uriStem] = 1;
            }
        }

        public List<(string Uri, int Count)> TopUris(int take)
        {
            if (_uriCounts is null || _uriCounts.Count == 0) return new();
            return _uriCounts
                .OrderByDescending(kv => kv.Value)
                .ThenBy(kv => kv.Key, StringComparer.OrdinalIgnoreCase)
                .Take(take)
                .Select(kv => (kv.Key, kv.Value))
                .ToList();
        }

        public string UaDisplay => UaMixed ? "(mixed)" : (Ua ?? "-");
        public int AvgTimeMs => TotalAll == 0 ? 0 : (int)(TimeTakenTotalMs / TotalAll);
        public double FourxxRatio => TotalAll == 0 ? 0 : (double)C4xx / TotalAll;
    }

    private sealed record BurstPick(string Id, string Display);

    private sealed class BurstWindow
    {
        public required string Id { get; init; }
        public required string Ip { get; init; }
        public required DateTime StartUtc { get; init; }
        public required DateTime EndUtc { get; init; }
        public required string OutPath { get; init; }
    }

    public static async Task RunAsync(SessionState session, CancellationToken ct = default)
    {
        var root = session.Root;

        ConsoleEx.Header("IIS: Find Bursts Patterns");

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

        var bucketChoice = AnsiConsole.Prompt(
            new SelectionPrompt<string>()
                .Title("Bucket size for burst detection")
                .PageSize(10)
                .AddChoices(new[]
                {
                    "10 seconds (microbursts)",
                    "30 seconds",
                    "60 seconds (default)",
                    "300 seconds (5 minutes)"
                })
        );

        var bucketSeconds = bucketChoice.StartsWith("10") ? 10
                         : bucketChoice.StartsWith("30") ? 30
                         : bucketChoice.StartsWith("300") ? 300
                         : 60;

        var rateThreshold = (int)Math.Ceiling(2.0 * bucketSeconds);
        var enumThreshold = Math.Max(10, (int)Math.Ceiling(0.5 * bucketSeconds));
        var errorThreshold = Math.Max(10, (int)Math.Ceiling((25.0 / 60.0) * bucketSeconds));

        var uniqueCap = Math.Max(enumThreshold + 1, 64);
        var uriCap = 40;

        var ignoreUAPrefixes = new[] { "ELB-HealthChecker/" };

        var aggs = new Dictionary<string, BurstAgg>(StringComparer.OrdinalIgnoreCase);
        IisW3cReader.FieldMap? firstMap = null;

        await AnsiConsole.Status()
            .Spinner(Spinner.Known.Dots)
            .StartAsync("Scanning IIS logs for bursts…", async ctx =>
            {
                for (int f = 0; f < files.Count; f++)
                {
                    ct.ThrowIfCancellationRequested();

                    var file = files[f];
                    ctx.Status($"Scanning… ({f + 1}/{files.Count}) {Path.GetFileName(file)}");

                    var map = await IisW3cReader.ReadFieldMapAsync(file, ct);
                    if (map is null)
                        continue;

                    firstMap ??= map;

                    if (!map.TryGetIndex("date", out var iDate)) continue;
                    if (!map.TryGetIndex("time", out var iTime)) continue;
                    if (!map.TryGetIndex("sc-status", out var iStatus)) continue;

                    map.TryGetIndex("cs-method", out var iMethod);
                    map.TryGetIndex("cs-uri-stem", out var iUriStem);
                    map.TryGetIndex("time-taken", out var iTimeTaken);
                    map.TryGetIndex("OriginalIP", out var iOriginalIp);
                    map.TryGetIndex("c-ip", out var iCIp);
                    map.TryGetIndex("cs(User-Agent)", out var iUA);

                    await IisW3cReader.ForEachDataLineAsync(file, ct, (rawLine, tokens) =>
                    {
                        if (!TryParseDateTimeUtc(tokens.Get(iDate), tokens.Get(iTime), out var tsUtc))
                            return;

                        var bucketStart = FloorToBucket(tsUtc, bucketSeconds);

                        if (!TryParseInt(tokens.Get(iStatus), out var status))
                            return;

                        if (iUA >= 0)
                        {
                            var uaSpan = tokens.Get(iUA);
                            if (!uaSpan.IsEmpty && uaSpan[0] != '-')
                            {
                                var uaStr = uaSpan.ToString();
                                for (int k = 0; k < ignoreUAPrefixes.Length; k++)
                                {
                                    if (uaStr.StartsWith(ignoreUAPrefixes[k], StringComparison.OrdinalIgnoreCase))
                                        return;
                                }
                            }
                        }

                        var ip = GetRealIpPreferOriginal(tokens, iOriginalIp, iCIp);
                        if (ip is null) return;
                        if (IsPrivateOrLoopback(ip)) return;

                        var key = $"{ip}|{bucketStart.Ticks}";
                        if (!aggs.TryGetValue(key, out var agg))
                        {
                            agg = new BurstAgg(uniqueCap, uriCap)
                            {
                                Ip = ip,
                                StartUtc = bucketStart,
                                BucketSeconds = bucketSeconds
                            };
                            aggs[key] = agg;
                        }

                        agg.TotalAll++;

                        if (iMethod >= 0)
                        {
                            var m = tokens.Get(iMethod);
                            if (!m.IsEmpty && m[0] != '-')
                            {
                                if (m.Equals("GET", StringComparison.OrdinalIgnoreCase)) agg.Get++;
                                else if (m.Equals("POST", StringComparison.OrdinalIgnoreCase)) agg.Post++;
                                else if (m.Equals("HEAD", StringComparison.OrdinalIgnoreCase)) agg.Head++;
                            }
                        }

                        if (status >= 200 && status <= 299) agg.C2xx++;
                        else if (status >= 300 && status <= 399) agg.C3xx++;
                        else if (status >= 400 && status <= 499) agg.C4xx++;
                        else if (status >= 500 && status <= 599) agg.C5xx++;

                        if (iTimeTaken >= 0 && TryParseInt(tokens.Get(iTimeTaken), out var ms))
                        {
                            agg.TimeTakenTotalMs += ms;
                            if (ms > agg.TimeTakenMaxMs) agg.TimeTakenMaxMs = ms;
                        }

                        if (iUA >= 0)
                        {
                            var ua = tokens.Get(iUA);
                            if (!ua.IsEmpty && ua[0] != '-')
                            {
                                var uaStr = ua.ToString();
                                if (agg.Ua is null) agg.Ua = uaStr;
                                else if (!agg.UaMixed && !string.Equals(agg.Ua, uaStr, StringComparison.OrdinalIgnoreCase))
                                    agg.UaMixed = true;
                            }
                        }

                        if (iUriStem >= 0)
                        {
                            var uri = tokens.Get(iUriStem);
                            if (!uri.IsEmpty && uri[0] != '-')
                            {
                                var uriStr = uri.ToString();
                                if (IsDynamicPath(uriStr))
                                {
                                    agg.TotalDynamic++;
                                    agg.AddDynamicUri(uriStr);
                                }
                            }
                        }
                    });
                }
            });

        if (aggs.Count == 0)
        {
            AnsiConsole.MarkupLine("[grey]No traffic buckets found (after filters).[/]");
            ConsoleEx.Pause();
            return;
        }

        var bursts = aggs.Values
            .Select(a => new
            {
                Agg = a,
                IsRate = a.TotalDynamic >= rateThreshold,
                IsEnum = a.UniqueDynamicUris >= enumThreshold,
                IsError = a.C4xx >= errorThreshold || (a.FourxxRatio >= 0.80 && a.TotalAll >= Math.Max(20, rateThreshold / 2)),
                SeverityScore = Score(a, rateThreshold, enumThreshold, errorThreshold)
            })
            .Where(x => x.IsRate || x.IsEnum || x.IsError)
            .OrderByDescending(x => x.SeverityScore)
            .ThenByDescending(x => x.Agg.TotalDynamic)
            .ThenByDescending(x => x.Agg.UniqueDynamicUris)
            .ThenByDescending(x => x.Agg.C4xx)
            .ThenBy(x => x.Agg.StartUtc)
            .Take(20)
            .ToList();

        if (bursts.Count == 0)
        {
            AnsiConsole.MarkupLine("[grey]No bursts matched the current heuristics.[/]");
            AnsiConsole.MarkupLine("[dim]Try smaller bucket size or expect fewer bursts for this time range.[/]");
            ConsoleEx.Pause();
            return;
        }

        ConsoleEx.Header("IIS: Burst buckets (Top 20)", $"Bucket: {bucketSeconds}s | Rate≥{rateThreshold} dyn | Unique≥{enumThreshold} | 4xx≥{errorThreshold}");

        var table = new Table()
            .RoundedBorder()
            .AddColumn("[bold]Rank[/]")
            .AddColumn("[bold]Start (UTC)[/]")
            .AddColumn("[bold]IP[/]")
            .AddColumn("[bold]Dyn[/]")
            .AddColumn("[bold]Unique[/]")
            .AddColumn("[bold]4xx%[/]")
            .AddColumn("[bold]POST[/]")
            .AddColumn("[bold]HEAD[/]")
            .AddColumn("[bold]Avg ms[/]")
            .AddColumn("[bold]UA[/]");

        for (int i = 0; i < bursts.Count; i++)
        {
            var a = bursts[i].Agg;

            table.AddRow(
                (i + 1).ToString(),
                a.StartUtc.ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture),
                a.Ip,
                a.TotalDynamic.ToString("n0", CultureInfo.InvariantCulture),
                a.UniqueDynamicUris.ToString("n0", CultureInfo.InvariantCulture),
                (a.FourxxRatio * 100).ToString("0.0", CultureInfo.InvariantCulture),
                a.Post.ToString("n0", CultureInfo.InvariantCulture),
                a.Head.ToString("n0", CultureInfo.InvariantCulture),
                a.AvgTimeMs.ToString("n0", CultureInfo.InvariantCulture),
                Markup.Escape(Truncate(a.UaDisplay, 40))
            );
        }

        AnsiConsole.Write(table);
        AnsiConsole.WriteLine();

        // --- NEW: Save burst IPs to session (replaces prior) ---
        if (ConsoleEx.ReadYesNo("Save burst IPs (distinct) to session? This replaces the previous burst-IP session.", defaultYes: true))
        {
            var set = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (var b in bursts)
                set.Add(b.Agg.Ip);

            session.ReplaceIisBurstIps(set);

            AnsiConsole.MarkupLine($"[green]Saved[/] {set.Count} IP(s) to session (updated {session.IisBurstIpsUpdatedUtc:yyyy-MM-dd HH:mm:ss}Z).");
            AnsiConsole.WriteLine();
        }

        // --- Selection (export) ---
        var pick = new MultiSelectionPrompt<BurstPick>()
            .Title("Select burst bucket(s) to export raw lines")
            .NotRequired()
            .PageSize(20)
            .InstructionsText("[grey](Space to toggle, Enter to confirm)[/]")
            .UseConverter(p => p.Display);

        pick.AddChoice(new BurstPick(SelectAllSentinel, "[bold][[Select ALL]][/] Export all bursts shown (Top 20)"));

        for (int i = 0; i < bursts.Count; i++)
        {
            var a = bursts[i].Agg;
            var id = $"{a.Ip}|{a.StartUtc.Ticks}";
            var flags = BurstFlags(a, rateThreshold, enumThreshold, errorThreshold);

            pick.AddChoice(new BurstPick(
                id,
                $"{i + 1}. {a.StartUtc:yyyy-MM-dd HH:mm:ss}Z | {a.Ip} | dyn:{a.TotalDynamic} unique:{a.UniqueDynamicUris} 4xx:{a.C4xx} | {flags}"
            ));
        }

        var selected = AnsiConsole.Prompt(pick);
        if (selected.Count == 0)
        {
            AnsiConsole.MarkupLine("[grey](no bursts selected)[/]");
            ConsoleEx.Pause();
            return;
        }

        HashSet<string> selectedIds;
        if (selected.Any(x => x.Id == SelectAllSentinel))
            selectedIds = bursts.Select(b => $"{b.Agg.Ip}|{b.Agg.StartUtc.Ticks}").ToHashSet(StringComparer.OrdinalIgnoreCase);
        else
            selectedIds = selected.Select(x => x.Id).ToHashSet(StringComparer.OrdinalIgnoreCase);

        var outDir = Path.Combine(root, "output");
        Directory.CreateDirectory(outDir);

        var batchDir = Path.Combine(outDir, $"iis_bursts_{DateTime.UtcNow:yyyyMMdd_HHmmss}");
        Directory.CreateDirectory(batchDir);

        var windows = new List<BurstWindow>();
        int outRank = 1;

        foreach (var b in bursts)
        {
            var id = $"{b.Agg.Ip}|{b.Agg.StartUtc.Ticks}";
            if (!selectedIds.Contains(id))
                continue;

            var safeIp = b.Agg.Ip.Replace(":", "_");
            var fileName = $"burst_{outRank:00}_{safeIp}_{b.Agg.StartUtc:yyyyMMdd_HHmmss}Z_{bucketSeconds}s.log";

            windows.Add(new BurstWindow
            {
                Id = id,
                Ip = b.Agg.Ip,
                StartUtc = b.Agg.StartUtc,
                EndUtc = b.Agg.StartUtc.AddSeconds(bucketSeconds),
                OutPath = Path.Combine(batchDir, fileName)
            });

            outRank++;
        }

        var writers = new Dictionary<string, StreamWriter>(StringComparer.OrdinalIgnoreCase);

        foreach (var w in windows)
        {
            var sw = new StreamWriter(File.Create(w.OutPath));

            if (firstMap is not null)
            {
                foreach (var h in firstMap.HeaderLines)
                    sw.WriteLine(h);
                sw.WriteLine(firstMap.FieldsLine);
            }
            else
            {
                sw.WriteLine("#Software: Microsoft Internet Information Services 10.0");
                sw.WriteLine("#Version: 1.0");
                sw.WriteLine($"#Date: {DateTime.UtcNow:yyyy-MM-dd HH:mm:ss}");
            }

            writers[w.Id] = sw;
        }

        var windowsByIp = windows
            .GroupBy(w => w.Ip, StringComparer.OrdinalIgnoreCase)
            .ToDictionary(g => g.Key, g => g.OrderBy(w => w.StartUtc).ToList(), StringComparer.OrdinalIgnoreCase);

        long exported = 0;

        await AnsiConsole.Status()
            .Spinner(Spinner.Known.Dots)
            .StartAsync("Exporting selected bursts…", async ctx =>
            {
                for (int f = 0; f < files.Count; f++)
                {
                    ct.ThrowIfCancellationRequested();

                    var file = files[f];
                    ctx.Status($"Exporting… ({f + 1}/{files.Count}) {Path.GetFileName(file)}");

                    var map = await IisW3cReader.ReadFieldMapAsync(file, ct);
                    if (map is null)
                        continue;

                    if (!map.TryGetIndex("date", out var iDate)) continue;
                    if (!map.TryGetIndex("time", out var iTime)) continue;

                    map.TryGetIndex("OriginalIP", out var iOriginalIp);
                    map.TryGetIndex("c-ip", out var iCIp);

                    await IisW3cReader.ForEachDataLineAsync(file, ct, (rawLine, tokens) =>
                    {
                        if (!TryParseDateTimeUtc(tokens.Get(iDate), tokens.Get(iTime), out var tsUtc))
                            return;

                        var ip = GetRealIpPreferOriginal(tokens, iOriginalIp, iCIp);
                        if (ip is null) return;

                        if (!windowsByIp.TryGetValue(ip, out var list))
                            return;

                        for (int i = 0; i < list.Count; i++)
                        {
                            var w = list[i];
                            if (tsUtc < w.StartUtc) continue;
                            if (tsUtc >= w.EndUtc) continue;

                            writers[w.Id].WriteLine(rawLine);
                            exported++;
                        }
                    });
                }
            });

        foreach (var sw in writers.Values)
            sw.Dispose();

        ConsoleEx.Header("IIS: Burst export complete");
        AnsiConsole.MarkupLine($"[dim]Bucket:[/] {bucketSeconds}s");
        AnsiConsole.MarkupLine($"[dim]Exported lines:[/] {exported:n0}");
        AnsiConsole.MarkupLine($"[dim]Output folder:[/] {Markup.Escape(batchDir)}");
        ConsoleEx.Pause();
    }

    private static int Score(BurstAgg a, int rateTh, int enumTh, int errTh)
    {
        int score = 0;

        if (a.TotalDynamic >= rateTh) score += 50 + (a.TotalDynamic - rateTh);
        if (a.UniqueDynamicUris >= enumTh) score += 40 + (a.UniqueDynamicUris - enumTh) * 2;

        if (a.C4xx >= errTh) score += 35 + (a.C4xx - errTh) * 2;
        else if (a.FourxxRatio >= 0.80 && a.TotalAll >= Math.Max(20, rateTh / 2)) score += 30;

        if (a.Post > 0) score += Math.Min(20, a.Post);
        if (a.Head > 0) score += Math.Min(10, a.Head);

        if (a.TimeTakenMaxMs >= 5000) score += 15;
        else if (a.TimeTakenMaxMs >= 2000) score += 8;

        return score;
    }

    private static string BurstFlags(BurstAgg a, int rateTh, int enumTh, int errTh)
    {
        var flags = new List<string>();

        if (a.TotalDynamic >= rateTh) flags.Add("RATE");
        if (a.UniqueDynamicUris >= enumTh) flags.Add("ENUM");
        if (a.C4xx >= errTh || (a.FourxxRatio >= 0.80 && a.TotalAll >= Math.Max(20, rateTh / 2))) flags.Add("4XX");

        if (a.Post > 0) flags.Add("POST");
        if (a.Head > 0) flags.Add("HEAD");

        return flags.Count == 0 ? "-" : string.Join("+", flags);
    }

    private static bool TryParseInt(ReadOnlySpan<char> s, out int value)
    {
        value = 0;
        if (s.IsEmpty || s[0] == '-') return false;
        return int.TryParse(s, NumberStyles.Integer, CultureInfo.InvariantCulture, out value);
    }

    private static bool TryParseDateTimeUtc(ReadOnlySpan<char> date, ReadOnlySpan<char> time, out DateTime dtUtc)
    {
        dtUtc = default;
        if (date.Length != 10 || time.Length < 8) return false;

        if (!TryParse2(date.Slice(0, 4), out var yyyy)) return false;
        if (!TryParse2(date.Slice(5, 2), out var mm)) return false;
        if (!TryParse2(date.Slice(8, 2), out var dd)) return false;

        if (!TryParse2(time.Slice(0, 2), out var hh)) return false;
        if (!TryParse2(time.Slice(3, 2), out var mi)) return false;
        if (!TryParse2(time.Slice(6, 2), out var ss)) return false;

        try
        {
            dtUtc = new DateTime(yyyy, mm, dd, hh, mi, ss, DateTimeKind.Utc);
            return true;
        }
        catch
        {
            return false;
        }
    }

    private static bool TryParse2(ReadOnlySpan<char> s, out int value)
    {
        value = 0;
        return int.TryParse(s, NumberStyles.Integer, CultureInfo.InvariantCulture, out value);
    }

    private static DateTime FloorToBucket(DateTime utc, int bucketSeconds)
    {
        var ticksPerBucket = TimeSpan.FromSeconds(bucketSeconds).Ticks;
        var floored = utc.Ticks - (utc.Ticks % ticksPerBucket);
        return new DateTime(floored, DateTimeKind.Utc);
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

        var comma = raw.IndexOf(',');
        if (comma >= 0)
            raw = raw.Slice(0, comma).Trim();

        if (raw.Length > 0 && raw[0] == '[')
        {
            var end = raw.IndexOf(']');
            if (end > 1)
                raw = raw.Slice(1, end - 1);
        }
        else
        {
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

    private static bool IsDynamicPath(string uriStem)
    {
        if (uriStem.StartsWith("/ServiceCenter", StringComparison.OrdinalIgnoreCase)) return true;
        if (uriStem.StartsWith("/LifeTime", StringComparison.OrdinalIgnoreCase)) return true;
        if (uriStem.Contains("/moduleservices", StringComparison.OrdinalIgnoreCase)) return true;
        if (uriStem.Contains("/rest/", StringComparison.OrdinalIgnoreCase)) return true;
        if (uriStem.Contains("/soap/", StringComparison.OrdinalIgnoreCase)) return true;
        if (uriStem.EndsWith(".asmx", StringComparison.OrdinalIgnoreCase)) return true;
        if (uriStem.EndsWith(".aspx", StringComparison.OrdinalIgnoreCase)) return true;

        var lastSlash = uriStem.LastIndexOf('/');
        var lastDot = uriStem.LastIndexOf('.');
        if (lastDot > lastSlash && lastDot >= 0)
        {
            var ext = uriStem.Substring(lastDot).ToLowerInvariant();
            return ext switch
            {
                ".js" or ".css" or ".png" or ".jpg" or ".jpeg" or ".gif" or ".svg" or ".ico" or ".woff" or ".woff2" or ".ttf" or ".map" or ".txt" or ".xml" => false,
                _ => true
            };
        }

        return true;
    }

    private static string Truncate(string s, int max)
        => s.Length <= max ? s : s.Substring(0, Math.Max(0, max - 1)) + "…";
}
