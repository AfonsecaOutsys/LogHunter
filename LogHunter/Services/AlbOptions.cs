using System.Text;
using LogHunter.Models;
using LogHunter.Utils;
using Spectre.Console;

namespace LogHunter.Services;

public static class AlbOptions
{
    private static long SumFileSizesSafe(List<string> files)
    {
        long total = 0;
        foreach (var f in files)
        {
            try { total += new FileInfo(f).Length; }
            catch { }
        }
        return total;
    }

    private struct UriAgg
    {
        public long Count;
        public double SumSeconds;
        public double MaxSeconds;
    }

    private static DateTime FloorTo5MinUtc(DateTime dtUtc)
    {
        dtUtc = dtUtc.Kind == DateTimeKind.Utc ? dtUtc : dtUtc.ToUniversalTime();
        int flooredMinute = (dtUtc.Minute / 5) * 5;
        return new DateTime(dtUtc.Year, dtUtc.Month, dtUtc.Day, dtUtc.Hour, flooredMinute, 0, DateTimeKind.Utc);
    }

    // ---------- Shared UX helpers (Spectre) ----------

    private static void InfoPanel(string title, params (string Key, string Value)[] rows)
    {
        var t = new Table().RoundedBorder().AddColumn("Field").AddColumn("Value");
        foreach (var (k, v) in rows)
            t.AddRow(Markup.Escape(k), Markup.Escape(v));
        AnsiConsole.Write(new Panel(t) { Header = new PanelHeader(title), Border = BoxBorder.Rounded });
        AnsiConsole.WriteLine();
    }

    private static Table TopTable(params string[] columns)
    {
        var t = new Table().RoundedBorder();
        foreach (var c in columns)
            t.AddColumn(new TableColumn(Markup.Escape(c)));
        return t;
    }

    private static async Task RunScanWithProgressAsync(
        string title,
        List<string> files,
        Func<string, Action<long>, Task> scanFileAsync)
    {
        var totalBytes = SumFileSizesSafe(files);

        await AnsiConsole.Progress()
            .AutoClear(false)
            .Columns(new ProgressColumn[]
            {
                new TaskDescriptionColumn(),
                new ProgressBarColumn(),
                new PercentageColumn(),
                new RemainingTimeColumn(),
                new SpinnerColumn()
            })
            .StartAsync(async ctx =>
            {
                var task = ctx.AddTask(title, maxValue: Math.Max(1, totalBytes));

                foreach (var file in files)
                {
                    await scanFileAsync(file, delta =>
                    {
                        if (delta <= 0) return;
                        task.Increment(delta);
                    }).ConfigureAwait(false);
                }

                // Ensure it reaches 100% even if deltas didn’t perfectly match total bytes
                if (task.Value < task.MaxValue)
                    task.Value = task.MaxValue;

                task.StopTask();
            });

        AnsiConsole.WriteLine();
    }

    // ---------- OPTION 6 ----------

    public static async Task TrackRequestsPerIpPer5MinAsync(string root)
    {
        var albFolder = AppFolders.ALB;
        var outputFolder = AppFolders.Output;

        ConsoleEx.Header("ALB: Track requests per IP per 5 minutes (up to 5 IPs)",
            $"Reading logs from: {albFolder}");

        if (!Directory.Exists(albFolder))
        {
            AnsiConsole.MarkupLine($"[red]ALB folder not found:[/] {Markup.Escape(albFolder)}");
            ConsoleEx.Pause();
            return;
        }

        // Gather up to 5 IPs
        var ips = new List<string>(capacity: 5);
        while (ips.Count < 5)
        {
            var next = ConsoleEx.Prompt($"Add IP #{ips.Count + 1} (blank to finish): ");
            if (string.IsNullOrWhiteSpace(next)) break;

            next = next.Trim();

            if (!IsLikelyIp(next))
            {
                AnsiConsole.MarkupLine("[yellow]That doesn't look like an IPv4 address. Try again.[/]");
                continue;
            }

            if (ips.Contains(next, StringComparer.Ordinal))
            {
                AnsiConsole.MarkupLine("[yellow]Already added.[/]");
                continue;
            }

            ips.Add(next);
        }

        if (ips.Count == 0)
        {
            AnsiConsole.MarkupLine("[yellow]No IPs provided.[/]");
            ConsoleEx.Pause();
            return;
        }

        var files = AlbScanner.GetLogFiles();
        if (files.Count == 0)
        {
            AnsiConsole.MarkupLine($"[yellow]No .log files found in:[/] {Markup.Escape(albFolder)}");
            ConsoleEx.Pause();
            return;
        }

        InfoPanel("Scan plan",
            ("Mode", "Requests per IP per 5 minutes"),
            ("IPs", string.Join(", ", ips)),
            ("Files", files.Count.ToString("N0")),
            ("Input", albFolder),
            ("Output", outputFolder));

        // IP -> bucket -> count
        var bucketsByIp = new Dictionary<string, SortedDictionary<DateTime, long>>(StringComparer.Ordinal);
        foreach (var ip in ips)
            bucketsByIp[ip] = new SortedDictionary<DateTime, long>();

        // We implement progress at file level (bytes in file), without changing your algorithm
        var totalBytes = SumFileSizesSafe(files);

        await AnsiConsole.Progress()
            .AutoClear(false)
            .Columns(new ProgressColumn[]
            {
                new TaskDescriptionColumn(),
                new ProgressBarColumn(),
                new PercentageColumn(),
                new RemainingTimeColumn(),
                new SpinnerColumn()
            })
            .StartAsync(async ctx =>
            {
                var task = ctx.AddTask("Scanning ALB logs", maxValue: Math.Max(1, totalBytes));

                foreach (var file in files)
                {
                    using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite, bufferSize: 1 << 20, FileOptions.SequentialScan);
                    using var sr = new StreamReader(fs, Encoding.UTF8, detectEncodingFromByteOrderMarks: true, bufferSize: 1 << 20);

                    long lastReportedPos = 0;
                    const long chunk = 64L * 1024 * 1024;

                    while (true)
                    {
                        var line = await sr.ReadLineAsync().ConfigureAwait(false);
                        if (line is null) break;
                        if (line.Length == 0) continue;

                        var ip = AlbScanner.ExtractAlbClientIp(line);
                        if (ip is null) continue;

                        if (!bucketsByIp.ContainsKey(ip))
                            continue;

                        var tsUtc = AlbScanner.ExtractAlbTimestampUtc(line);
                        if (tsUtc is null) continue;

                        var bucket = FloorTo5MinUtc(tsUtc.Value);

                        var map = bucketsByIp[ip];
                        if (map.TryGetValue(bucket, out var cur))
                            map[bucket] = cur + 1;
                        else
                            map[bucket] = 1;

                        var pos = fs.Position;
                        if (pos - lastReportedPos >= chunk)
                        {
                            task.Increment(pos - lastReportedPos);
                            lastReportedPos = pos;
                        }
                    }

                    var remaining = fs.Length - lastReportedPos;
                    if (remaining > 0)
                        task.Increment(remaining);
                }

                if (task.Value < task.MaxValue)
                    task.Value = task.MaxValue;

                task.StopTask();
            });

        AnsiConsole.WriteLine();

        // Build unified timeline
        var allBuckets = new SortedSet<DateTime>();
        foreach (var ip in ips)
            foreach (var b in bucketsByIp[ip].Keys)
                allBuckets.Add(b);

        if (allBuckets.Count == 0)
        {
            AnsiConsole.MarkupLine("[yellow]No matches found for those IPs.[/]");
            ConsoleEx.Pause();
            return;
        }

        // Export CSV
        Directory.CreateDirectory(outputFolder);
        var stamp = DateTime.Now.ToString("yyyyMMdd_HHmmss");
        var csvFile = Path.Combine(outputFolder, $"ALB_RequestsPer5Min_{stamp}.csv");

        using (var w = new StreamWriter(csvFile, false, Encoding.UTF8))
        {
            w.Write("BucketStartUtc");
            foreach (var ip in ips) w.Write($",{ip}");
            w.WriteLine();

            foreach (var b in allBuckets)
            {
                w.Write(b.ToString("yyyy-MM-dd HH:mm:ss 'UTC'"));
                foreach (var ip in ips)
                {
                    bucketsByIp[ip].TryGetValue(b, out var c);
                    w.Write($",{c}");
                }
                w.WriteLine();
            }
        }

        AnsiConsole.MarkupLine($"Exported CSV: [green]{Markup.Escape(csvFile)}[/]");

        // Build series for chart (shared timeline)
        var times = allBuckets.ToArray();
        var series = new List<(string SeriesName, DateTime[] TimesUtc, double[] Values)>(ips.Count);

        foreach (var ip in ips)
        {
            var ys = new double[times.Length];
            var map = bucketsByIp[ip];

            for (int i = 0; i < times.Length; i++)
            {
                map.TryGetValue(times[i], out var c);
                ys[i] = c;
            }

            series.Add((ip, times, ys));
        }

        var html = Charts.SaveTimeSeriesHtmlAndOpen(
            outputFolder: outputFolder,
            title: "ALB Requests per IP per 5 minutes",
            yLabel: "Requests",
            series: series,
            filePrefix: "ALB_RequestsPer5Min");

        AnsiConsole.MarkupLine($"Chart (offline HTML): [green]{Markup.Escape(html)}[/]");
        ConsoleEx.Pause();
    }

    // ---------- OPTION 2 ----------

    public static async Task TopIpsForEndpointAsync(string root, List<SavedSelection> savedSelections)
    {
        var albFolder = AppFolders.ALB;
        var outputFolder = AppFolders.Output;

        ConsoleEx.Header("ALB: Top IPs for endpoint/path fragment (optimized)",
            $"Reading logs from: {albFolder}");

        if (!Directory.Exists(albFolder))
        {
            AnsiConsole.MarkupLine($"[red]ALB folder not found:[/] {Markup.Escape(albFolder)}");
            ConsoleEx.Pause();
            return;
        }

        var endpoint = ConsoleEx.Prompt("Paste endpoint/path fragment (example: ActionLogin_Wrapper): ");
        if (string.IsNullOrWhiteSpace(endpoint))
        {
            AnsiConsole.MarkupLine("[yellow]No endpoint provided.[/]");
            ConsoleEx.Pause();
            return;
        }

        var files = AlbScanner.GetLogFiles();
        if (files.Count == 0)
        {
            AnsiConsole.MarkupLine($"[yellow]No .log files found in:[/] {Markup.Escape(albFolder)}");
            ConsoleEx.Pause();
            return;
        }

        InfoPanel("Scan plan",
            ("Mode", "Top IPs for endpoint"),
            ("Endpoint fragment", endpoint),
            ("Files", files.Count.ToString("N0")),
            ("Input", albFolder));

        var ipCounts = new Dictionary<string, int>(StringComparer.Ordinal);

        await RunScanWithProgressAsync(
            title: "Scanning ALB logs",
            files: files,
            scanFileAsync: (file, reportDelta) =>
                AlbScanner.ScanFileForEndpointIpCountsAsync(
                    filePath: file,
                    endpointFragment: endpoint,
                    ipCounts: ipCounts,
                    reportBytesDelta: reportDelta)
        );

        if (ipCounts.Count == 0)
        {
            AnsiConsole.MarkupLine($"[yellow]No hits found for '{Markup.Escape(endpoint)}'.[/]");
            ConsoleEx.Pause();
            return;
        }

        var top = ipCounts
            .OrderByDescending(kvp => kvp.Value)
            .Take(50)
            .Select((kvp, idx) => new { Rank = idx + 1, IP = kvp.Key, Hits = kvp.Value })
            .ToList();

        var table = TopTable("Rank", "Hits", "IP");
        foreach (var row in top)
            table.AddRow(row.Rank.ToString(), row.Hits.ToString("N0"), Markup.Escape(row.IP));

        AnsiConsole.Write(new Panel(table) { Header = new PanelHeader($"Top IPs hitting '{endpoint}' (max 50)"), Border = BoxBorder.Rounded });
        AnsiConsole.WriteLine();

        var maxRank = top.Max(x => x.Rank);
        var n = AnsiConsole.Prompt(
            new TextPrompt<int>($"Choose the [bold]LAST rank[/] to save (1-{maxRank}). Example: 2 saves rank 1 and 2:")
                .Validate(v => v >= 1 && v <= maxRank
                    ? ValidationResult.Success()
                    : ValidationResult.Error($"Enter a number between 1 and {maxRank}."))
        );

        var selected = top.Where(x => x.Rank <= n).ToList();

        var utcNow = DateTime.UtcNow;
        foreach (var row in selected)
        {
            savedSelections.Add(new SavedSelection(
                SavedAtUtc: utcNow,
                Source: "ALB",
                Endpoint: endpoint,
                Rank: row.Rank,
                IP: row.IP,
                Hits: row.Hits
            ));
        }

        AnsiConsole.MarkupLine($"Saved top [bold]{n}[/] IP(s) to session list.");

        var doExport = ConsoleEx.ReadYesNo("Export THESE saved IPs to a file now?", defaultYes: true);
        if (doExport)
        {
            Directory.CreateDirectory(outputFolder);
            var stamp = DateTime.Now.ToString("yyyyMMdd_HHmmss");
            var outFile = Path.Combine(outputFolder, $"ALB_SelectedTop{n}_{stamp}.csv");

            using var swCsv = new StreamWriter(outFile, false, Encoding.UTF8);
            swCsv.WriteLine("Rank,IP,Hits");
            foreach (var row in selected)
                swCsv.WriteLine($"{row.Rank},{row.IP},{row.Hits}");

            AnsiConsole.MarkupLine($"Exported: [green]{Markup.Escape(outFile)}[/]");
        }

        ConsoleEx.Pause();
    }

    // ---------- OPTION 3 ----------

    public static async Task Top50IpsOverallAsync(string root)
    {
        var albFolder = AppFolders.ALB;
        var outputFolder = AppFolders.Output;

        ConsoleEx.Header("ALB: Top 50 IPs overall (optimized)",
            $"Reading logs from: {albFolder}");

        if (!Directory.Exists(albFolder))
        {
            AnsiConsole.MarkupLine($"[red]ALB folder not found:[/] {Markup.Escape(albFolder)}");
            ConsoleEx.Pause();
            return;
        }

        var files = AlbScanner.GetLogFiles();
        if (files.Count == 0)
        {
            AnsiConsole.MarkupLine($"[yellow]No .log files found in:[/] {Markup.Escape(albFolder)}");
            ConsoleEx.Pause();
            return;
        }

        InfoPanel("Scan plan",
            ("Mode", "Top 50 IPs overall"),
            ("Files", files.Count.ToString("N0")),
            ("Input", albFolder));

        var ipCounts = new Dictionary<string, int>(StringComparer.Ordinal);

        await RunScanWithProgressAsync(
            title: "Scanning ALB logs",
            files: files,
            scanFileAsync: (file, reportDelta) =>
                AlbScanner.ScanFileForOverallIpCountsAsync(
                    filePath: file,
                    ipCounts: ipCounts,
                    reportBytesDelta: reportDelta)
        );

        if (ipCounts.Count == 0)
        {
            AnsiConsole.MarkupLine("[yellow]No IPs found.[/]");
            ConsoleEx.Pause();
            return;
        }

        var top = ipCounts
            .OrderByDescending(kvp => kvp.Value)
            .Take(50)
            .Select((kvp, idx) => new { Rank = idx + 1, IP = kvp.Key, Hits = kvp.Value })
            .ToList();

        var table = TopTable("Rank", "Hits", "IP");
        foreach (var row in top)
            table.AddRow(row.Rank.ToString(), row.Hits.ToString("N0"), Markup.Escape(row.IP));

        AnsiConsole.Write(new Panel(table) { Header = new PanelHeader("Top 50 IPs overall"), Border = BoxBorder.Rounded });
        AnsiConsole.WriteLine();

        var doExport = ConsoleEx.ReadYesNo("Export Top 50 IPs to file?", defaultYes: true);
        if (doExport)
        {
            Directory.CreateDirectory(outputFolder);
            var stamp = DateTime.Now.ToString("yyyyMMdd_HHmmss");
            var outFile = Path.Combine(outputFolder, $"ALB_Top50_IPs_{stamp}.csv");

            using var swCsv = new StreamWriter(outFile, false, Encoding.UTF8);
            swCsv.WriteLine("Rank,IP,Hits");
            foreach (var row in top)
                swCsv.WriteLine($"{row.Rank},{row.IP},{row.Hits}");

            AnsiConsole.MarkupLine($"Exported: [green]{Markup.Escape(outFile)}[/]");
        }

        ConsoleEx.Pause();
    }

    // ---------- OPTION 4 ----------

    public static async Task Top50IpUriNoQueryAsync(string root)
    {
        var albFolder = AppFolders.ALB;
        var outputFolder = AppFolders.Output;

        ConsoleEx.Header("ALB: Top 50 (IP + URI) without query string (optimized)",
            $"Reading logs from: {albFolder}");

        if (!Directory.Exists(albFolder))
        {
            AnsiConsole.MarkupLine($"[red]ALB folder not found:[/] {Markup.Escape(albFolder)}");
            ConsoleEx.Pause();
            return;
        }

        var files = AlbScanner.GetLogFiles();
        if (files.Count == 0)
        {
            AnsiConsole.MarkupLine($"[yellow]No .log files found in:[/] {Markup.Escape(albFolder)}");
            ConsoleEx.Pause();
            return;
        }

        InfoPanel("Scan plan",
            ("Mode", "Top 50 IP + URI (no query)"),
            ("Files", files.Count.ToString("N0")),
            ("Input", albFolder));

        var pairCounts = new Dictionary<string, int>(StringComparer.Ordinal);

        await RunScanWithProgressAsync(
            title: "Scanning ALB logs",
            files: files,
            scanFileAsync: (file, reportDelta) =>
                AlbScanner.ScanFileForIpUriCountsAsync(
                    filePath: file,
                    pairCounts: pairCounts,
                    reportBytesDelta: reportDelta)
        );

        if (pairCounts.Count == 0)
        {
            AnsiConsole.MarkupLine("[yellow]No results found.[/]");
            ConsoleEx.Pause();
            return;
        }

        var top = pairCounts
            .OrderByDescending(kvp => kvp.Value)
            .Take(50)
            .Select((kvp, idx) =>
            {
                var key = kvp.Key;
                var tab = key.IndexOf('\t');
                var ip = tab > 0 ? key[..tab] : key;
                var uri = (tab > 0 && tab + 1 < key.Length) ? key[(tab + 1)..] : "";
                return new { Rank = idx + 1, IP = ip, URI = uri, Hits = kvp.Value };
            })
            .ToList();

        var table = TopTable("Rank", "Hits", "IP", "URI");
        foreach (var row in top)
            table.AddRow(row.Rank.ToString(), row.Hits.ToString("N0"), Markup.Escape(row.IP), Markup.Escape(row.URI));

        AnsiConsole.Write(new Panel(table) { Header = new PanelHeader("Top 50 IP + URI (no query)"), Border = BoxBorder.Rounded });
        AnsiConsole.WriteLine();

        var doExport = ConsoleEx.ReadYesNo("Export Top 50 IP+URI to file?", defaultYes: true);
        if (doExport)
        {
            Directory.CreateDirectory(outputFolder);
            var stamp = DateTime.Now.ToString("yyyyMMdd_HHmmss");
            var outFile = Path.Combine(outputFolder, $"ALB_Top50_IPs_NoQuery_URIs_{stamp}.csv");

            using var swCsv = new StreamWriter(outFile, false, Encoding.UTF8);
            swCsv.WriteLine("Rank,Hits,IP,URI");
            foreach (var row in top)
            {
                var uri = row.URI.Replace("\"", "\"\"");
                swCsv.WriteLine($"{row.Rank},{row.Hits},{row.IP},\"{uri}\"");
            }

            AnsiConsole.MarkupLine($"Exported: [green]{Markup.Escape(outFile)}[/]");
        }

        ConsoleEx.Pause();
    }

    // ---------- OPTION 5 ----------

    public static async Task AvgDurationByTargetNoQueryAsync(string root)
    {
        var albFolder = AppFolders.ALB;
        var outputFolder = AppFolders.Output;

        ConsoleEx.Header("ALB: Requests (no query) ordered by AVG duration, filtered by target",
            $"Reading logs from: {albFolder}");

        if (!Directory.Exists(albFolder))
        {
            AnsiConsole.MarkupLine($"[red]ALB folder not found:[/] {Markup.Escape(albFolder)}");
            ConsoleEx.Pause();
            return;
        }

        var target = ConsoleEx.Prompt("Target (IP or fragment to match, example: 10.0.0.12): ");
        if (string.IsNullOrWhiteSpace(target))
        {
            AnsiConsole.MarkupLine("[yellow]No target provided.[/]");
            ConsoleEx.Pause();
            return;
        }

        var files = AlbScanner.GetLogFiles();
        if (files.Count == 0)
        {
            AnsiConsole.MarkupLine($"[yellow]No .log files found in:[/] {Markup.Escape(albFolder)}");
            ConsoleEx.Pause();
            return;
        }

        InfoPanel("Scan plan",
            ("Mode", "AVG duration by target (no query URI)"),
            ("Target filter", target),
            ("Files", files.Count.ToString("N0")),
            ("Input", albFolder));

        var stats = new Dictionary<string, UriAgg>(StringComparer.Ordinal);

        var totalBytes = SumFileSizesSafe(files);

        await AnsiConsole.Progress()
            .AutoClear(false)
            .Columns(new ProgressColumn[]
            {
                new TaskDescriptionColumn(),
                new ProgressBarColumn(),
                new PercentageColumn(),
                new RemainingTimeColumn(),
                new SpinnerColumn()
            })
            .StartAsync(async ctx =>
            {
                var task = ctx.AddTask("Scanning ALB logs", maxValue: Math.Max(1, totalBytes));

                foreach (var file in files)
                {
                    using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite, bufferSize: 1 << 20, FileOptions.SequentialScan);
                    using var sr = new StreamReader(fs, Encoding.UTF8, detectEncodingFromByteOrderMarks: true, bufferSize: 1 << 20);

                    long lastReportedPos = 0;
                    const long chunk = 64L * 1024 * 1024;

                    while (true)
                    {
                        var line = await sr.ReadLineAsync().ConfigureAwait(false);
                        if (line is null) break;
                        if (line.Length == 0) continue;

                        var targetHost = AlbScanner.ExtractAlbTargetHost(line);
                        if (targetHost is null) continue;
                        if (targetHost.IndexOf(target, StringComparison.OrdinalIgnoreCase) < 0) continue;

                        var dur = AlbScanner.ExtractAlbTargetProcessingTimeSeconds(line);
                        if (dur is null || dur.Value < 0) continue;

                        var uri = AlbScanner.ExtractAlbUriNoQuery(line);
                        if (string.IsNullOrEmpty(uri)) continue;

                        if (!stats.TryGetValue(uri, out var agg))
                            agg = default;

                        agg.Count++;
                        agg.SumSeconds += dur.Value;
                        if (dur.Value > agg.MaxSeconds) agg.MaxSeconds = dur.Value;

                        stats[uri] = agg;

                        var pos = fs.Position;
                        if (pos - lastReportedPos >= chunk)
                        {
                            task.Increment(pos - lastReportedPos);
                            lastReportedPos = pos;
                        }
                    }

                    var remaining = fs.Length - lastReportedPos;
                    if (remaining > 0)
                        task.Increment(remaining);
                }

                if (task.Value < task.MaxValue)
                    task.Value = task.MaxValue;

                task.StopTask();
            });

        AnsiConsole.WriteLine();

        if (stats.Count == 0)
        {
            AnsiConsole.MarkupLine($"[yellow]No matches found for target filter:[/] {Markup.Escape(target)}");
            ConsoleEx.Pause();
            return;
        }

        var results = stats
            .Select(kvp =>
            {
                var uri = kvp.Key;
                var agg = kvp.Value;
                var avg = agg.Count > 0 ? agg.SumSeconds / agg.Count : 0.0;
                return new
                {
                    AvgSeconds = avg,
                    Count = agg.Count,
                    MaxSeconds = agg.MaxSeconds,
                    URI = uri
                };
            })
            .OrderByDescending(x => x.AvgSeconds)
            .Take(50)
            .Select((x, idx) => new { Rank = idx + 1, x.AvgSeconds, x.Count, x.MaxSeconds, x.URI })
            .ToList();

        var table = TopTable("Rank", "AVG (s)", "COUNT", "MAX (s)", "URI");
        foreach (var r in results)
            table.AddRow(
                r.Rank.ToString(),
                r.AvgSeconds.ToString("0.000"),
                r.Count.ToString("N0"),
                r.MaxSeconds.ToString("0.000"),
                Markup.Escape(r.URI));

        AnsiConsole.Write(new Panel(table)
        {
            Header = new PanelHeader($"Top 50 URIs (no query), filtered by target '{target}', ordered by AVG duration"),
            Border = BoxBorder.Rounded
        });
        AnsiConsole.WriteLine();

        var doExport = ConsoleEx.ReadYesNo("Export these results to file?", defaultYes: true);
        if (doExport)
        {
            Directory.CreateDirectory(outputFolder);
            var stamp = DateTime.Now.ToString("yyyyMMdd_HHmmss");
            var outFile = Path.Combine(outputFolder, $"ALB_AvgDuration_ByTarget_{stamp}.csv");

            using var swCsv = new StreamWriter(outFile, false, Encoding.UTF8);
            swCsv.WriteLine("AvgSeconds,Count,MaxSeconds,URI");

            foreach (var r in results)
            {
                var uriEsc = r.URI.Replace("\"", "\"\"");
                swCsv.WriteLine($"{r.AvgSeconds:0.000},{r.Count},{r.MaxSeconds:0.000},\"{uriEsc}\"");
            }

            AnsiConsole.MarkupLine($"Exported: [green]{Markup.Escape(outFile)}[/]");
        }

        ConsoleEx.Pause();
    }

    // ---------- OPTION 7 ----------

    public static async Task WafBlockedSummaryAsync(string root)
    {
        var albFolder = AppFolders.ALB;
        var outputFolder = AppFolders.Output;

        ConsoleEx.Header("ALB: WAF blocked summary + Top 50 blocked requests",
            $"Reading logs from: {albFolder}");

        if (!Directory.Exists(albFolder))
        {
            AnsiConsole.MarkupLine($"[red]ALB folder not found:[/] {Markup.Escape(albFolder)}");
            ConsoleEx.Pause();
            return;
        }

        var files = AlbScanner.GetLogFiles();
        if (files.Count == 0)
        {
            AnsiConsole.MarkupLine($"[yellow]No .log files found in:[/] {Markup.Escape(albFolder)}");
            ConsoleEx.Pause();
            return;
        }

        InfoPanel("Scan plan",
            ("Mode", "WAF blocked summary"),
            ("Files", files.Count.ToString("N0")),
            ("Input", albFolder));

        var totalBytes = SumFileSizesSafe(files);

        long total = 0;
        long blocked = 0;

        var blockedCounts = new Dictionary<string, int>(StringComparer.Ordinal);

        await AnsiConsole.Progress()
            .AutoClear(false)
            .Columns(new ProgressColumn[]
            {
                new TaskDescriptionColumn(),
                new ProgressBarColumn(),
                new PercentageColumn(),
                new RemainingTimeColumn(),
                new SpinnerColumn()
            })
            .StartAsync(async ctx =>
            {
                var task = ctx.AddTask("Scanning ALB logs", maxValue: Math.Max(1, totalBytes));

                foreach (var file in files)
                {
                    using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite, bufferSize: 1 << 20, FileOptions.SequentialScan);
                    using var sr = new StreamReader(fs, Encoding.UTF8, detectEncodingFromByteOrderMarks: true, bufferSize: 1 << 20);

                    long lastReportedPos = 0;
                    const long chunk = 64L * 1024 * 1024;

                    while (true)
                    {
                        var line = await sr.ReadLineAsync().ConfigureAwait(false);
                        if (line is null) break;
                        if (line.Length == 0) continue;

                        total++;

                        if (!line.Contains("waf,forward", StringComparison.OrdinalIgnoreCase))
                        {
                            blocked++;

                            var ip = AlbScanner.ExtractAlbClientIp(line);
                            if (ip is not null)
                            {
                                var uri = AlbScanner.ExtractAlbUriNoQuery(line) ?? "";
                                var key = $"{ip}\t{uri}";

                                if (blockedCounts.TryGetValue(key, out var cur))
                                    blockedCounts[key] = cur + 1;
                                else
                                    blockedCounts[key] = 1;
                            }
                        }

                        var pos = fs.Position;
                        if (pos - lastReportedPos >= chunk)
                        {
                            task.Increment(pos - lastReportedPos);
                            lastReportedPos = pos;
                        }
                    }

                    var remaining = fs.Length - lastReportedPos;
                    if (remaining > 0)
                        task.Increment(remaining);
                }

                if (task.Value < task.MaxValue)
                    task.Value = task.MaxValue;

                task.StopTask();
            });

        AnsiConsole.WriteLine();

        InfoPanel("Summary",
            ("Total entries parsed", total.ToString("N0")),
            ("Blocked entries (per definition)", blocked.ToString("N0")));

        if (blockedCounts.Count == 0)
        {
            AnsiConsole.MarkupLine("[yellow]No blocked requests found (or blocked entries had no parseable IP/URI).[/]");
            ConsoleEx.Pause();
            return;
        }

        var top = blockedCounts
            .OrderByDescending(kvp => kvp.Value)
            .Take(50)
            .Select((kvp, idx) =>
            {
                var key = kvp.Key;
                var tab = key.IndexOf('\t');
                var ip = tab > 0 ? key[..tab] : key;
                var uri = (tab > 0 && tab + 1 < key.Length) ? key[(tab + 1)..] : "";
                return new { Rank = idx + 1, IP = ip, URI = uri, Hits = kvp.Value };
            })
            .ToList();

        var table = TopTable("Rank", "Hits", "IP", "URI");
        foreach (var row in top)
            table.AddRow(row.Rank.ToString(), row.Hits.ToString("N0"), Markup.Escape(row.IP), Markup.Escape(row.URI));

        AnsiConsole.Write(new Panel(table) { Header = new PanelHeader("Top 50 blocked (IP + URI)"), Border = BoxBorder.Rounded });
        AnsiConsole.WriteLine();

        var doExport = ConsoleEx.ReadYesNo("Export blocked Top 50 to file?", defaultYes: true);
        if (doExport)
        {
            Directory.CreateDirectory(outputFolder);
            var stamp = DateTime.Now.ToString("yyyyMMdd_HHmmss");
            var outFile = Path.Combine(outputFolder, $"ALB_WAF_Blocked_Top50_{stamp}.csv");

            using var swCsv = new StreamWriter(outFile, false, Encoding.UTF8);
            swCsv.WriteLine("Rank,Hits,IP,URI");
            foreach (var row in top)
            {
                var uri = row.URI.Replace("\"", "\"\"");
                swCsv.WriteLine($"{row.Rank},{row.Hits},{row.IP},\"{uri}\"");
            }

            AnsiConsole.MarkupLine($"Exported: [green]{Markup.Escape(outFile)}[/]");
        }

        ConsoleEx.Pause();
    }

    private static bool IsLikelyIp(string s)
    {
        var parts = s.Split('.', StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length != 4) return false;

        foreach (var p in parts)
        {
            if (!int.TryParse(p, out int n)) return false;
            if (n < 0 || n > 255) return false;
        }
        return true;
    }
}
