using System.Text;
using LogHunter.Models;
using LogHunter.Utils;

namespace LogHunter.Services;

public static class AlbOptions
{
    private static void WriteOverallProgressBar(
        ref long processedBytes,
        long deltaBytes,
        long totalBytes,
        System.Diagnostics.Stopwatch sw,
        ref long lastRenderMs,
        string label)
    {
        processedBytes += deltaBytes;

        var ms = sw.ElapsedMilliseconds;
        if (ms - lastRenderMs < 100 && processedBytes < totalBytes) return;
        lastRenderMs = ms;

        double pct = totalBytes > 0 ? (processedBytes / (double)totalBytes) * 100.0 : 0.0;
        ConsoleEx.DrawProgressBar(label, pct, barWidth: 36);
    }

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

    // OPTION 6 (UPDATED): interactive offline HTML chart
    public static async Task TrackRequestsPerIpPer5MinAsync(string root)
    {
        var albFolder = AppFolders.ALB;
        var outputFolder = AppFolders.Output;

        ConsoleEx.Header("ALB: Track requests per IP per 5 minutes (up to 5 IPs)",
            $"Reading logs from: {albFolder}");

        if (!Directory.Exists(albFolder))
        {
            Console.WriteLine($"ALB folder not found: {albFolder}");
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
                Console.WriteLine("That doesn't look like an IPv4 address. Try again.");
                continue;
            }

            if (ips.Contains(next, StringComparer.Ordinal))
            {
                Console.WriteLine("Already added.");
                continue;
            }

            ips.Add(next);
        }

        if (ips.Count == 0)
        {
            Console.WriteLine("No IPs provided.");
            ConsoleEx.Pause();
            return;
        }

        var files = AlbScanner.GetLogFiles();
        if (files.Count == 0)
        {
            Console.WriteLine($"No .log files found in: {albFolder}");
            ConsoleEx.Pause();
            return;
        }

        var totalBytes = SumFileSizesSafe(files);

        Console.WriteLine($"Tracking {ips.Count} IP(s). Found {files.Count} file(s). Scanning...");
        Console.WriteLine();

        // IP -> bucket -> count
        var bucketsByIp = new Dictionary<string, SortedDictionary<DateTime, long>>(StringComparer.Ordinal);
        foreach (var ip in ips)
            bucketsByIp[ip] = new SortedDictionary<DateTime, long>();

        long processed = 0;
        var sw = System.Diagnostics.Stopwatch.StartNew();
        long lastRenderMs = 0;

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

                // only parse timestamp if IP matches (saves CPU)
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
                    WriteOverallProgressBar(ref processed, pos - lastReportedPos, totalBytes, sw, ref lastRenderMs, "Scanning ALB logs...");
                    lastReportedPos = pos;
                }
            }

            var remaining = fs.Length - lastReportedPos;
            if (remaining > 0)
                WriteOverallProgressBar(ref processed, remaining, totalBytes, sw, ref lastRenderMs, "Scanning ALB logs...");
        }

        ConsoleEx.DrawProgressBar("Scanning ALB logs...", 100.0, barWidth: 36);
        Console.WriteLine();
        Console.WriteLine();

        // Build unified timeline
        var allBuckets = new SortedSet<DateTime>();
        foreach (var ip in ips)
            foreach (var b in bucketsByIp[ip].Keys)
                allBuckets.Add(b);

        if (allBuckets.Count == 0)
        {
            Console.WriteLine("No matches found for those IPs.");
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

        Console.WriteLine($"Exported CSV: {csvFile}");

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

        Console.WriteLine($"Chart (offline HTML): {html}");
        ConsoleEx.Pause();
    }

    private static void PrintBucketRows(
        List<DateTime> buckets,
        List<string> ips,
        Dictionary<string, SortedDictionary<DateTime, long>> bucketsByIp)
    {
        Console.Write("BucketStartUtc           ");
        foreach (var ip in ips) Console.Write($" {ip,15}");
        Console.WriteLine();

        Console.WriteLine(new string('-', 24 + (ips.Count * 16)));

        foreach (var b in buckets)
        {
            Console.Write($"{b:yyyy-MM-dd HH:mm} UTC  ");
            foreach (var ip in ips)
            {
                bucketsByIp[ip].TryGetValue(b, out var c);
                Console.Write($"{c,15}");
            }
            Console.WriteLine();
        }

        Console.WriteLine();
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

    // OPTION 2
    public static async Task TopIpsForEndpointAsync(string root, List<SavedSelection> savedSelections)
    {
        var albFolder = AppFolders.ALB;
        var outputFolder = AppFolders.Output;

        ConsoleEx.Header("ALB: Top IPs for endpoint/path fragment (optimized)",
            $"Reading logs from: {albFolder}");

        if (!Directory.Exists(albFolder))
        {
            Console.WriteLine($"ALB folder not found: {albFolder}");
            ConsoleEx.Pause();
            return;
        }

        var endpoint = ConsoleEx.Prompt("Paste endpoint/path fragment (example: ActionLogin_Wrapper): ");
        if (string.IsNullOrWhiteSpace(endpoint))
        {
            Console.WriteLine("No endpoint provided.");
            ConsoleEx.Pause();
            return;
        }

        var files = AlbScanner.GetLogFiles();
        if (files.Count == 0)
        {
            Console.WriteLine($"No .log files found in: {albFolder}");
            ConsoleEx.Pause();
            return;
        }

        var totalBytes = SumFileSizesSafe(files);

        Console.WriteLine($"Found {files.Count} file(s). Scanning...");
        Console.WriteLine();

        var ipCounts = new Dictionary<string, int>(StringComparer.Ordinal);

        long processed = 0;
        var sw = System.Diagnostics.Stopwatch.StartNew();
        long lastRenderMs = 0;

        foreach (var file in files)
        {
            await AlbScanner.ScanFileForEndpointIpCountsAsync(
                filePath: file,
                endpointFragment: endpoint,
                ipCounts: ipCounts,
                reportBytesDelta: delta => WriteOverallProgressBar(ref processed, delta, totalBytes, sw, ref lastRenderMs, "Scanning ALB logs...")
            );
        }

        ConsoleEx.DrawProgressBar("Scanning ALB logs...", 100.0, barWidth: 36);
        Console.WriteLine();
        Console.WriteLine();

        if (ipCounts.Count == 0)
        {
            Console.WriteLine($"No hits found for '{endpoint}'.");
            ConsoleEx.Pause();
            return;
        }

        var top = ipCounts
            .OrderByDescending(kvp => kvp.Value)
            .Take(50)
            .Select((kvp, idx) => new { Rank = idx + 1, IP = kvp.Key, Hits = kvp.Value })
            .ToList();

        Console.WriteLine($"Top IPs hitting '{endpoint}' (max 50):");
        Console.WriteLine();
        foreach (var row in top)
            Console.WriteLine($"{row.Rank,2}.  {row.Hits,10}  {row.IP}");

        Console.WriteLine();
        var maxRank = top.Max(x => x.Rank);
        var n = ConsoleEx.PromptIntInRange(
            $"Choose the LAST rank to save (1-{maxRank}). Example: 2 saves rank 1 and 2: ",
            1, maxRank
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

        Console.WriteLine();
        Console.WriteLine($"Saved top {n} IP(s) to session list.");

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

            Console.WriteLine($"Exported: {outFile}");
        }

        ConsoleEx.Pause();
    }

    // OPTION 3
    public static async Task Top50IpsOverallAsync(string root)
    {
        var albFolder = AppFolders.ALB;
        var outputFolder = AppFolders.Output;

        ConsoleEx.Header("ALB: Top 50 IPs overall (optimized)",
            $"Reading logs from: {albFolder}");

        if (!Directory.Exists(albFolder))
        {
            Console.WriteLine($"ALB folder not found: {albFolder}");
            ConsoleEx.Pause();
            return;
        }

        var files = AlbScanner.GetLogFiles();
        if (files.Count == 0)
        {
            Console.WriteLine($"No .log files found in: {albFolder}");
            ConsoleEx.Pause();
            return;
        }

        var totalBytes = SumFileSizesSafe(files);

        Console.WriteLine($"Found {files.Count} file(s). Scanning...");
        Console.WriteLine();

        var ipCounts = new Dictionary<string, int>(StringComparer.Ordinal);

        long processed = 0;
        var sw = System.Diagnostics.Stopwatch.StartNew();
        long lastRenderMs = 0;

        foreach (var file in files)
        {
            await AlbScanner.ScanFileForOverallIpCountsAsync(
                filePath: file,
                ipCounts: ipCounts,
                reportBytesDelta: delta => WriteOverallProgressBar(ref processed, delta, totalBytes, sw, ref lastRenderMs, "Scanning ALB logs...")
            );
        }

        ConsoleEx.DrawProgressBar("Scanning ALB logs...", 100.0, barWidth: 36);
        Console.WriteLine();
        Console.WriteLine();

        var top = ipCounts
            .OrderByDescending(kvp => kvp.Value)
            .Take(50)
            .Select(kvp => new { IP = kvp.Key, Hits = kvp.Value })
            .ToList();

        Console.WriteLine("Top 50 IPs overall:");
        Console.WriteLine();
        foreach (var row in top)
            Console.WriteLine($"{row.Hits,10}  {row.IP}");

        Console.WriteLine();
        var doExport = ConsoleEx.ReadYesNo("Export Top 50 IPs to file?", defaultYes: true);
        if (doExport)
        {
            Directory.CreateDirectory(outputFolder);
            var stamp = DateTime.Now.ToString("yyyyMMdd_HHmmss");
            var outFile = Path.Combine(outputFolder, $"ALB_Top50_IPs_{stamp}.csv");

            using var swCsv = new StreamWriter(outFile, false, Encoding.UTF8);
            swCsv.WriteLine("IP,Hits");
            foreach (var row in top)
                swCsv.WriteLine($"{row.IP},{row.Hits}");

            Console.WriteLine($"Exported: {outFile}");
        }

        ConsoleEx.Pause();
    }

    // OPTION 4
    public static async Task Top50IpUriNoQueryAsync(string root)
    {
        var albFolder = AppFolders.ALB;
        var outputFolder = AppFolders.Output;

        ConsoleEx.Header("ALB: Top 50 (IP + URI) without query string (optimized)",
            $"Reading logs from: {albFolder}");

        if (!Directory.Exists(albFolder))
        {
            Console.WriteLine($"ALB folder not found: {albFolder}");
            ConsoleEx.Pause();
            return;
        }

        var files = AlbScanner.GetLogFiles();
        if (files.Count == 0)
        {
            Console.WriteLine($"No .log files found in: {albFolder}");
            ConsoleEx.Pause();
            return;
        }

        var totalBytes = SumFileSizesSafe(files);

        Console.WriteLine($"Found {files.Count} file(s). Scanning...");
        Console.WriteLine();

        var pairCounts = new Dictionary<string, int>(StringComparer.Ordinal);

        long processed = 0;
        var sw = System.Diagnostics.Stopwatch.StartNew();
        long lastRenderMs = 0;

        foreach (var file in files)
        {
            await AlbScanner.ScanFileForIpUriCountsAsync(
                filePath: file,
                pairCounts: pairCounts,
                reportBytesDelta: delta => WriteOverallProgressBar(ref processed, delta, totalBytes, sw, ref lastRenderMs, "Scanning ALB logs...")
            );
        }

        ConsoleEx.DrawProgressBar("Scanning ALB logs...", 100.0, barWidth: 36);
        Console.WriteLine();
        Console.WriteLine();

        var top = pairCounts
            .OrderByDescending(kvp => kvp.Value)
            .Take(50)
            .Select(kvp =>
            {
                var key = kvp.Key;
                var tab = key.IndexOf('\t');
                var ip = tab > 0 ? key[..tab] : key;
                var uri = (tab > 0 && tab + 1 < key.Length) ? key[(tab + 1)..] : "";
                return new { IP = ip, URI = uri, Hits = kvp.Value };
            })
            .ToList();

        Console.WriteLine("Top 50 IP + URI (no query):");
        Console.WriteLine();
        foreach (var row in top)
            Console.WriteLine($"{row.Hits,10}  {row.IP,-15}  {row.URI}");

        Console.WriteLine();
        var doExport = ConsoleEx.ReadYesNo("Export Top 50 IP+URI to file?", defaultYes: true);
        if (doExport)
        {
            Directory.CreateDirectory(outputFolder);
            var stamp = DateTime.Now.ToString("yyyyMMdd_HHmmss");
            var outFile = Path.Combine(outputFolder, $"ALB_Top50_IPs_NoQuery_URIs_{stamp}.csv");

            using var swCsv = new StreamWriter(outFile, false, Encoding.UTF8);
            swCsv.WriteLine("IP,URI,Hits");
            foreach (var row in top)
            {
                var uri = row.URI.Replace("\"", "\"\"");
                swCsv.WriteLine($"{row.IP},\"{uri}\",{row.Hits}");
            }

            Console.WriteLine($"Exported: {outFile}");
        }

        ConsoleEx.Pause();
    }

    // OPTION 5
    public static async Task AvgDurationByTargetNoQueryAsync(string root)
    {
        var albFolder = AppFolders.ALB;
        var outputFolder = AppFolders.Output;

        ConsoleEx.Header("ALB: Requests (no query) ordered by AVG duration, filtered by target",
            $"Reading logs from: {albFolder}");

        if (!Directory.Exists(albFolder))
        {
            Console.WriteLine($"ALB folder not found: {albFolder}");
            ConsoleEx.Pause();
            return;
        }

        var target = ConsoleEx.Prompt("Target (IP or fragment to match, example: 10.0.0.12): ");
        if (string.IsNullOrWhiteSpace(target))
        {
            Console.WriteLine("No target provided.");
            ConsoleEx.Pause();
            return;
        }

        var files = AlbScanner.GetLogFiles();
        if (files.Count == 0)
        {
            Console.WriteLine($"No .log files found in: {albFolder}");
            ConsoleEx.Pause();
            return;
        }

        var totalBytes = SumFileSizesSafe(files);

        Console.WriteLine($"Found {files.Count} file(s). Scanning...");
        Console.WriteLine();

        var stats = new Dictionary<string, UriAgg>(StringComparer.Ordinal);

        long processed = 0;
        var sw = System.Diagnostics.Stopwatch.StartNew();
        long lastRenderMs = 0;

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
                    var delta = pos - lastReportedPos;
                    WriteOverallProgressBar(ref processed, delta, totalBytes, sw, ref lastRenderMs, "Scanning ALB logs...");
                    lastReportedPos = pos;
                }
            }

            var remaining = fs.Length - lastReportedPos;
            if (remaining > 0)
                WriteOverallProgressBar(ref processed, remaining, totalBytes, sw, ref lastRenderMs, "Scanning ALB logs...");
        }

        ConsoleEx.DrawProgressBar("Scanning ALB logs...", 100.0, barWidth: 36);
        Console.WriteLine();
        Console.WriteLine();

        if (stats.Count == 0)
        {
            Console.WriteLine($"No matches found for target filter: {target}");
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
            .ToList();

        Console.WriteLine($"Top 50 URIs (no query), filtered by target '{target}', ordered by AVG duration (desc):");
        Console.WriteLine();
        Console.WriteLine($"{"AVG(s)",10}  {"COUNT",10}  {"MAX(s)",10}  URI");
        Console.WriteLine(new string('-', 90));

        foreach (var r in results)
            Console.WriteLine($"{r.AvgSeconds,10:0.000}  {r.Count,10}  {r.MaxSeconds,10:0.000}  {r.URI}");

        Console.WriteLine();
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

            Console.WriteLine($"Exported: {outFile}");
        }

        ConsoleEx.Pause();
    }

    // OPTION 7
    public static async Task WafBlockedSummaryAsync(string root)
    {
        var albFolder = AppFolders.ALB;
        var outputFolder = AppFolders.Output;

        ConsoleEx.Header("ALB: WAF blocked summary + Top 50 blocked requests",
            $"Reading logs from: {albFolder}");

        if (!Directory.Exists(albFolder))
        {
            Console.WriteLine($"ALB folder not found: {albFolder}");
            ConsoleEx.Pause();
            return;
        }

        var files = AlbScanner.GetLogFiles();
        if (files.Count == 0)
        {
            Console.WriteLine($"No .log files found in: {albFolder}");
            ConsoleEx.Pause();
            return;
        }

        var totalBytes = SumFileSizesSafe(files);

        Console.WriteLine($"Found {files.Count} file(s). Scanning...");
        Console.WriteLine();

        long processed = 0;
        var sw = System.Diagnostics.Stopwatch.StartNew();
        long lastRenderMs = 0;

        long total = 0;
        long blocked = 0;

        var blockedCounts = new Dictionary<string, int>(StringComparer.Ordinal);

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

                if (line.Contains("waf,forward", StringComparison.OrdinalIgnoreCase))
                {
                    // not blocked (per your definition)
                }
                else
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
                    WriteOverallProgressBar(ref processed, pos - lastReportedPos, totalBytes, sw, ref lastRenderMs, "Scanning ALB logs...");
                    lastReportedPos = pos;
                }
            }

            var remaining = fs.Length - lastReportedPos;
            if (remaining > 0)
                WriteOverallProgressBar(ref processed, remaining, totalBytes, sw, ref lastRenderMs, "Scanning ALB logs...");
        }

        ConsoleEx.DrawProgressBar("Scanning ALB logs...", 100.0, barWidth: 36);
        Console.WriteLine();
        Console.WriteLine();

        Console.WriteLine($"Total entries parsed: {total:N0}");
        Console.WriteLine($"Blocked entries (per your definition): {blocked:N0}");
        Console.WriteLine();

        if (blockedCounts.Count == 0)
        {
            Console.WriteLine("No blocked requests found (or blocked entries had no parseable IP/URI).");
            ConsoleEx.Pause();
            return;
        }

        var top = blockedCounts
            .OrderByDescending(kvp => kvp.Value)
            .Take(50)
            .Select(kvp =>
            {
                var key = kvp.Key;
                var tab = key.IndexOf('\t');
                var ip = tab > 0 ? key[..tab] : key;
                var uri = (tab > 0 && tab + 1 < key.Length) ? key[(tab + 1)..] : "";
                return new { IP = ip, URI = uri, Hits = kvp.Value };
            })
            .ToList();

        Console.WriteLine("Top 50 blocked (IP + URI):");
        Console.WriteLine();
        foreach (var row in top)
            Console.WriteLine($"{row.Hits,10}  {row.IP,-15}  {row.URI}");

        Console.WriteLine();
        var doExport = ConsoleEx.ReadYesNo("Export blocked Top 50 to file?", defaultYes: true);
        if (doExport)
        {
            Directory.CreateDirectory(outputFolder);
            var stamp = DateTime.Now.ToString("yyyyMMdd_HHmmss");
            var outFile = Path.Combine(outputFolder, $"ALB_WAF_Blocked_Top50_{stamp}.csv");

            using var swCsv = new StreamWriter(outFile, false, Encoding.UTF8);
            swCsv.WriteLine("IP,URI,Hits");
            foreach (var row in top)
            {
                var uri = row.URI.Replace("\"", "\"\"");
                swCsv.WriteLine($"{row.IP},\"{uri}\",{row.Hits}");
            }

            Console.WriteLine($"Exported: {outFile}");
        }

        ConsoleEx.Pause();
    }
}
