using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
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
            catch { /* ignore */ }
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

        AnsiConsole.Write(new Panel(t)
        {
            Header = new PanelHeader(Markup.Escape(title)),
            Border = BoxBorder.Rounded
        });

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

                // Ensure 100% even if deltas don't perfectly match file sizes.
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

        ConsoleEx.Header("ALB: Requests per IP (5-minute buckets)",
            $"Reading logs from: {albFolder}");

        if (!Directory.Exists(albFolder))
        {
            ConsoleEx.Error($"ALB folder not found: {albFolder}");
            ConsoleEx.Pause("Press Enter to return...");
            return;
        }

        // Gather up to 5 IPs
        var ips = new List<string>(capacity: 5);
        while (ips.Count < 5)
        {
            var next = ConsoleEx.ReadLineWithEsc($"Add IP #{ips.Count + 1} (blank to finish):");
            if (next is null)
            {
                ConsoleEx.Info("Cancelled.");
                ConsoleEx.Pause("Press Enter to return...");
                return;
            }

            if (string.IsNullOrWhiteSpace(next))
                break;

            next = next.Trim();

            if (!IsLikelyIp(next))
            {
                ConsoleEx.Warn("That does not look like an IPv4 address. Try again.");
                continue;
            }

            if (ips.Contains(next, StringComparer.Ordinal))
            {
                ConsoleEx.Warn("Already added.");
                continue;
            }

            ips.Add(next);
        }

        if (ips.Count == 0)
        {
            ConsoleEx.Warn("No IPs provided.");
            ConsoleEx.Pause("Press Enter to return...");
            return;
        }

        var files = AlbScanner.GetLogFiles();
        if (files.Count == 0)
        {
            ConsoleEx.Warn($"No .log files found in: {albFolder}");
            ConsoleEx.Pause("Press Enter to return...");
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

                        if (!bucketsByIp.TryGetValue(ip, out var map))
                            continue;

                        var tsUtc = AlbScanner.ExtractAlbTimestampUtc(line);
                        if (tsUtc is null) continue;

                        var bucket = FloorTo5MinUtc(tsUtc.Value);

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
            ConsoleEx.Warn("No matches found for those IPs.");
            ConsoleEx.Pause("Press Enter to return...");
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

        ConsoleEx.Success($"Exported CSV: {csvFile}");

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

        ConsoleEx.Success($"Chart (offline HTML): {html}");
        ConsoleEx.Pause("Press Enter to return...");
    }

    // ---------- OPTION 2 ----------

    public static async Task TopIpsForEndpointAsync(string root, List<SavedSelection> _savedSelections)
    {
        var albFolder = AppFolders.ALB;
        var outputFolder = AppFolders.Output;

        ConsoleEx.Header("ALB: Top full paths by IP for endpoint/path fragment",
            $"Reading logs from: {albFolder}");

        if (!Directory.Exists(albFolder))
        {
            ConsoleEx.Error($"ALB folder not found: {albFolder}");
            ConsoleEx.Pause("Press Enter to return...");
            return;
        }

        var endpoint = ConsoleEx.Prompt("Endpoint/path fragment (e.g., login or /login/):");
        if (string.IsNullOrWhiteSpace(endpoint))
        {
            ConsoleEx.Warn("No endpoint provided.");
            ConsoleEx.Pause("Press Enter to return...");
            return;
        }

        var files = AlbScanner.GetLogFiles();
        if (files.Count == 0)
        {
            ConsoleEx.Warn($"No .log files found in: {albFolder}");
            ConsoleEx.Pause("Press Enter to return...");
            return;
        }

        const int topIpCount = 20;
        const int topUriPerIpCount = 10;

        InfoPanel("Scan plan",
            ("Mode", "Top IPs for endpoint fragment + top full paths per IP (no query)"),
            ("Endpoint fragment", endpoint),
            ("Passes", "2"),
            ("Top IPs", topIpCount.ToString(CultureInfo.InvariantCulture)),
            ("Top URIs per IP", topUriPerIpCount.ToString(CultureInfo.InvariantCulture)),
            ("Files", files.Count.ToString("N0")),
            ("Input", albFolder));

        var endpointIpCounts = new Dictionary<string, int>(StringComparer.Ordinal);

        await RunScanWithProgressAsync(
            title: "Scanning ALB logs (pass 1/2: top IPs for fragment)",
            files: files,
            scanFileAsync: (file, reportDelta) =>
                AlbScanner.ScanFileForEndpointIpCountsAsync(
                    filePath: file,
                    endpointFragment: endpoint,
                    ipCounts: endpointIpCounts,
                    reportBytesDelta: reportDelta)
        );

        if (endpointIpCounts.Count == 0)
        {
            ConsoleEx.Warn($"No hits found for: {endpoint}");
            ConsoleEx.Pause("Press Enter to return...");
            return;
        }

        var topUris = uriCounts
            .OrderByDescending(kvp => kvp.Value)
            .Take(topUriCount)
            .Select((kvp, idx) => new { Rank = idx + 1, URI = kvp.Key, Hits = kvp.Value })
            .ToList();

        var selectedUris = new HashSet<string>(topUris.Select(x => x.URI), StringComparer.Ordinal);

        // Pass 2: only for top IPs, count URI hits by IP.
        var uriCountsByIp = new Dictionary<string, Dictionary<string, int>>(StringComparer.Ordinal);

        await RunScanWithProgressAsync(
            title: "Scanning ALB logs (pass 2/2: top full paths per top IP)",
            files: files,
            scanFileAsync: (file, reportDelta) =>
                AlbScanner.ScanFileForEndpointUriCountsBySelectedIpsAsync(
                    filePath: file,
                    endpointFragment: endpoint,
                    selectedIps: selectedIps,
                    uriCountsByIp: uriCountsByIp,
                    reportBytesDelta: reportDelta)
        );

        var topIpsTable = TopTable("IP Rank", "Hits", "IP");
        foreach (var row in topIps)
            topIpsTable.AddRow(
                row.Rank.ToString(CultureInfo.InvariantCulture),
                row.Hits.ToString("N0", CultureInfo.InvariantCulture),
                Markup.Escape(row.IP));

        AnsiConsole.Write(new Panel(topIpsTable)
        {
            Header = new PanelHeader($"Top IPs matching fragment: {Markup.Escape(endpoint)} (max {topIpCount})"),
            Border = BoxBorder.Rounded
        });
        AnsiConsole.WriteLine();

        var topIpsByUri = topUris
            .Select(uriRow =>
            {
                var topIps = uriIpPairCounts
                    .Where(kvp =>
                    {
                        var sep = kvp.Key.IndexOf('\t');
                        return sep > 0 && string.Equals(kvp.Key[(sep + 1)..], uriRow.URI, StringComparison.Ordinal);
                    })
                    .Select(kvp =>
                    {
                        var sep = kvp.Key.IndexOf('\t');
                        return new { IP = kvp.Key[..sep], Hits = kvp.Value };
                    })
                    .OrderByDescending(x => x.Hits)
                    .ThenBy(x => x.IP, StringComparer.Ordinal)
                    .Take(topIpPerUriCount)
                    .ToList();

                return new { Uri = uriRow, TopIps = topIps };
            })
            .ToList();

        foreach (var group in topIpsByUri)
        {
            var ipsTable = TopTable("IP Rank", "Hits", "IP");
            if (group.TopIps.Count == 0)
            {
                ipsTable.AddRow("-", "0", "(no IP matches)");
            }
            else
            {
                for (int i = 0; i < group.TopIps.Count; i++)
                {
                    var row = group.TopIps[i];
                    ipsTable.AddRow(
                        (i + 1).ToString(CultureInfo.InvariantCulture),
                        row.Hits.ToString("N0", CultureInfo.InvariantCulture),
                        Markup.Escape(row.IP));
                }
            }

            AnsiConsole.Write(new Panel(ipsTable)
            {
                Header = new PanelHeader(
                    $"URI #{group.Uri.Rank}: {Markup.Escape(group.Uri.URI)} ({group.Uri.Hits:N0} hits)"),
                Border = BoxBorder.Rounded
            });
            AnsiConsole.WriteLine();
        }

        var doExport = ConsoleEx.ReadYesNo("Export these results now?", defaultYes: true);
        if (doExport)
        {
            Directory.CreateDirectory(outputFolder);
            var stamp = DateTime.Now.ToString("yyyyMMdd_HHmmss");
            var outFile = Path.Combine(outputFolder, $"ALB_TopUris_TopIps_ForFragment_{stamp}.csv");

            using var swCsv = new StreamWriter(outFile, false, Encoding.UTF8);
            swCsv.WriteLine("UriRank,UriHits,URI,IpRank,IpHits,IP");
            foreach (var group in topIpsByUri)
            {
                if (group.TopIps.Count == 0)
                {
                    var onlyUri = group.Uri.URI.Replace("\"", "\"\"");
                    swCsv.WriteLine($"{group.Uri.Rank},{group.Uri.Hits},\"{onlyUri}\",0,0,\"\"");
                    continue;
                }

                for (int i = 0; i < group.TopIps.Count; i++)
                {
                    var row = group.TopIps[i];
                    var uri = group.Uri.URI.Replace("\"", "\"\"");
                    var ip = row.IP.Replace("\"", "\"\"");
                    swCsv.WriteLine($"{group.Uri.Rank},{group.Uri.Hits},\"{uri}\",{i + 1},{row.Hits},\"{ip}\"");
                }
            }

            ConsoleEx.Success($"Exported: {outFile}");
        }

        ConsoleEx.Pause("Press Enter to return...");
    }

    // ---------- OPTION 3 ----------

    public static async Task Top50IpsOverallAsync(string root)
    {
        var albFolder = AppFolders.ALB;
        var outputFolder = AppFolders.Output;

        ConsoleEx.Header("ALB: Top 50 IPs overall",
            $"Reading logs from: {albFolder}");

        if (!Directory.Exists(albFolder))
        {
            ConsoleEx.Error($"ALB folder not found: {albFolder}");
            ConsoleEx.Pause("Press Enter to return...");
            return;
        }

        var files = AlbScanner.GetLogFiles();
        if (files.Count == 0)
        {
            ConsoleEx.Warn($"No .log files found in: {albFolder}");
            ConsoleEx.Pause("Press Enter to return...");
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
            ConsoleEx.Warn("No IPs found.");
            ConsoleEx.Pause("Press Enter to return...");
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

        AnsiConsole.Write(new Panel(table)
        {
            Header = new PanelHeader("Top 50 IPs overall"),
            Border = BoxBorder.Rounded
        });
        AnsiConsole.WriteLine();

        var doExport = ConsoleEx.ReadYesNo("Export these results now?", defaultYes: true);
        if (doExport)
        {
            Directory.CreateDirectory(outputFolder);
            var stamp = DateTime.Now.ToString("yyyyMMdd_HHmmss");
            var outFile = Path.Combine(outputFolder, $"ALB_Top50_IPs_{stamp}.csv");

            using var swCsv = new StreamWriter(outFile, false, Encoding.UTF8);
            swCsv.WriteLine("Rank,IP,Hits");
            foreach (var row in top)
                swCsv.WriteLine($"{row.Rank},{row.IP},{row.Hits}");

            ConsoleEx.Success($"Exported: {outFile}");
        }

        ConsoleEx.Pause("Press Enter to return...");
    }

    // ---------- OPTION 4 ----------

    public static async Task Top50IpUriNoQueryAsync(string root)
    {
        var albFolder = AppFolders.ALB;
        var outputFolder = AppFolders.Output;

        ConsoleEx.Header("ALB: Top 50 IPs by URI (no query)",
            $"Reading logs from: {albFolder}");

        if (!Directory.Exists(albFolder))
        {
            ConsoleEx.Error($"ALB folder not found: {albFolder}");
            ConsoleEx.Pause("Press Enter to return...");
            return;
        }

        var files = AlbScanner.GetLogFiles();
        if (files.Count == 0)
        {
            ConsoleEx.Warn($"No .log files found in: {albFolder}");
            ConsoleEx.Pause("Press Enter to return...");
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
            ConsoleEx.Warn("No results found.");
            ConsoleEx.Pause("Press Enter to return...");
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

        AnsiConsole.Write(new Panel(table)
        {
            Header = new PanelHeader("Top 50 IP + URI (no query)"),
            Border = BoxBorder.Rounded
        });
        AnsiConsole.WriteLine();

        var doExport = ConsoleEx.ReadYesNo("Export these results now?", defaultYes: true);
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

            ConsoleEx.Success($"Exported: {outFile}");
        }

        ConsoleEx.Pause("Press Enter to return...");
    }

    // ---------- OPTION 5 ----------

    public static async Task Top50RequestsByAvgDurationNoQueryAsync(string root)
    {
        var albFolder = AppFolders.ALB;
        var outputFolder = AppFolders.Output;

        ConsoleEx.Header("ALB: Top 50 requests by AVG duration",
            $"Reading logs from: {albFolder}");

        if (!Directory.Exists(albFolder))
        {
            ConsoleEx.Error($"ALB folder not found: {albFolder}");
            ConsoleEx.Pause("Press Enter to return...");
            return;
        }

        var files = AlbScanner.GetLogFiles();
        if (files.Count == 0)
        {
            ConsoleEx.Warn($"No .log files found in: {albFolder}");
            ConsoleEx.Pause("Press Enter to return...");
            return;
        }

        InfoPanel("Scan plan",
            ("Mode", "Top 50 requests by AVG duration (URI without query)"),
            ("Files", files.Count.ToString("N0")),
            ("Input", albFolder));

        var stats = new Dictionary<string, UriAgg>(StringComparer.Ordinal);
        var totalBytes = SumFileSizesSafe(files);

        // ✅ Ctrl+C cancels scanning and returns (doesn't kill the app)
        var cancelled = false;
        ConsoleCancelEventHandler? cancelHandler = (_, e) =>
        {
            e.Cancel = true;
            cancelled = true;
        };

        Console.CancelKeyPress += cancelHandler;

        try
        {
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
                    var task = ctx.AddTask("Scanning ALB logs (Ctrl+C to cancel)", maxValue: Math.Max(1, totalBytes));

                    foreach (var file in files)
                    {
                        if (cancelled) break;

                        using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite, bufferSize: 1 << 20, FileOptions.SequentialScan);
                        using var sr = new StreamReader(fs, Encoding.UTF8, detectEncodingFromByteOrderMarks: true, bufferSize: 1 << 20);

                        long lastReportedPos = 0;
                        const long chunk = 64L * 1024 * 1024;

                        while (!cancelled)
                        {
                            var line = await sr.ReadLineAsync().ConfigureAwait(false);
                            if (line is null) break;
                            if (line.Length == 0) continue;

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
        }
        finally
        {
            Console.CancelKeyPress -= cancelHandler;
        }

        if (cancelled)
        {
            ConsoleEx.Warn("Cancelled.");
            ConsoleEx.Pause("Press Enter to return...");
            return;
        }

        if (stats.Count == 0)
        {
            ConsoleEx.Warn("No request duration data found in parsed logs.");
            ConsoleEx.Pause("Press Enter to return...");
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
            Header = new PanelHeader("Top 50 requests (URI no query) by AVG duration"),
            Border = BoxBorder.Rounded
        });
        AnsiConsole.WriteLine();

        var doExport = ConsoleEx.ReadYesNo("Export these results now?", defaultYes: true);
        if (doExport)
        {
            Directory.CreateDirectory(outputFolder);
            var stamp = DateTime.Now.ToString("yyyyMMdd_HHmmss");
            var outFile = Path.Combine(outputFolder, $"ALB_Top50_Requests_AvgDuration_{stamp}.csv");

            using var swCsv = new StreamWriter(outFile, false, Encoding.UTF8);
            swCsv.WriteLine("AvgSeconds,Count,MaxSeconds,URI");

            foreach (var r in results)
            {
                var uriEsc = r.URI.Replace("\"", "\"\"");
                swCsv.WriteLine($"{r.AvgSeconds:0.000},{r.Count},{r.MaxSeconds:0.000},\"{uriEsc}\"");
            }

            ConsoleEx.Success($"Exported: {outFile}");
        }

        ConsoleEx.Pause("Press Enter to return...");
    }

    // ---------- OPTION 7 ----------

    public static async Task WafBlockedSummaryAsync(string root)
    {
        var albFolder = AppFolders.ALB;
        var outputFolder = AppFolders.Output;

        ConsoleEx.Header("ALB: WAF blocked summary",
            $"Reading logs from: {albFolder}");

        if (!Directory.Exists(albFolder))
        {
            ConsoleEx.Error($"ALB folder not found: {albFolder}");
            ConsoleEx.Pause("Press Enter to return...");
            return;
        }

        var files = AlbScanner.GetLogFiles();
        if (files.Count == 0)
        {
            ConsoleEx.Warn($"No .log files found in: {albFolder}");
            ConsoleEx.Pause("Press Enter to return...");
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

                        // Current definition: blocked == NOT "waf,forward"
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
            ("Blocked entries", $"{blocked:N0} (entries without 'waf,forward')"));

        if (blockedCounts.Count == 0)
        {
            ConsoleEx.Warn("No blocked requests found (or blocked entries had no parseable IP/URI).");
            ConsoleEx.Pause("Press Enter to return...");
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

        AnsiConsole.Write(new Panel(table)
        {
            Header = new PanelHeader("Top 50 blocked (IP + URI)"),
            Border = BoxBorder.Rounded
        });
        AnsiConsole.WriteLine();

        var doExport = ConsoleEx.ReadYesNo("Export these results now?", defaultYes: true);
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

            ConsoleEx.Success($"Exported: {outFile}");
        }

        ConsoleEx.Pause("Press Enter to return...");
    }

    // ---------- OPTION 8 ----------

    public static async Task WafBlockedPerMinuteChartAsync(string root)
    {
        var albFolder = AppFolders.ALB;
        var outputFolder = AppFolders.Output;

        ConsoleEx.Header("ALB: WAF blocks over time (per minute)",
            $"Reading logs from: {albFolder}");

        if (!Directory.Exists(albFolder))
        {
            ConsoleEx.Error($"ALB folder not found: {albFolder}");
            ConsoleEx.Pause("Press Enter to return...");
            return;
        }

        var files = AlbScanner.GetLogFiles();
        if (files.Count == 0)
        {
            ConsoleEx.Warn($"No .log files found in: {albFolder}");
            ConsoleEx.Pause("Press Enter to return...");
            return;
        }

        // Minute bucket -> blocked count
        var buckets = new SortedDictionary<DateTime, long>();
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

                        // Same blocked definition as the summary view.
                        if (!line.Contains("waf,forward", StringComparison.OrdinalIgnoreCase))
                        {
                            var tsUtc = AlbScanner.ExtractAlbTimestampUtc(line);
                            if (tsUtc is not null)
                            {
                                var t = tsUtc.Value.Kind == DateTimeKind.Utc ? tsUtc.Value : tsUtc.Value.ToUniversalTime();
                                var minute = new DateTime(t.Year, t.Month, t.Day, t.Hour, t.Minute, 0, DateTimeKind.Utc);

                                if (buckets.TryGetValue(minute, out var cur))
                                    buckets[minute] = cur + 1;
                                else
                                    buckets[minute] = 1;
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

        if (buckets.Count == 0)
        {
            ConsoleEx.Warn("No blocked entries found (per current definition).");
            ConsoleEx.Pause("Press Enter to return...");
            return;
        }

        Directory.CreateDirectory(outputFolder);

        var times = buckets.Keys.ToArray();
        var ys = new double[times.Length];
        for (int i = 0; i < times.Length; i++)
            ys[i] = buckets[times[i]];

        var series = new List<(string SeriesName, DateTime[] TimesUtc, double[] Values)>(1)
        {
            ("Blocked/min", times, ys)
        };

        var html = Charts.SaveTimeSeriesHtmlAndOpen(
            outputFolder: outputFolder,
            title: "ALB WAF blocks over time (per minute)",
            yLabel: "Blocked requests",
            series: series,
            filePrefix: "ALB_WAF_BlockedPerMin");

        ConsoleEx.Success($"Chart (offline HTML): {html}");
        ConsoleEx.Pause("Press Enter to return...");
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
