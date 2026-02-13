using System.Diagnostics;
using System.IO.Compression;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using LogHunter.Utils;
using Spectre.Console;

namespace LogHunter.Services;

public static class AlbDownload
{
    // ALB object keys typically contain: ..._YYYYMMDDTHHMMZ_...
    // Example: ..._20230426T1215Z_...
    private static readonly Regex AlbTimestampRegex =
        new(@"_(\d{8})T(\d{4})Z_", RegexOptions.Compiled | RegexOptions.CultureInvariant);

    public static async Task RunAsync()
    {
        AppFolders.Ensure();

        ConsoleEx.Header("ALB - Download logs", $"Destination: {AppFolders.ALB}");

        // 1) Credentials
        AnsiConsole.MarkupLine("[grey]Paste the 3 AWS env lines (AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY / AWS_SESSION_TOKEN).[/]");
        AnsiConsole.MarkupLine("[grey]Finish by entering an empty line.[/]");
        AnsiConsole.WriteLine();

        var pasted = ReadMultiline();
        var creds = ParseAwsEnvVars(pasted);

        if (!creds.IsValid)
        {
            AnsiConsole.MarkupLine("[red]Couldn't parse credentials.[/]");
            AnsiConsole.MarkupLine("Expected lines like:");
            AnsiConsole.MarkupLine("  SET AWS_ACCESS_KEY_ID=...");
            AnsiConsole.MarkupLine("  SET AWS_SECRET_ACCESS_KEY=...");
            AnsiConsole.MarkupLine("  SET AWS_SESSION_TOKEN=...");
            ConsoleEx.Pause();
            return;
        }

        // 2) Standard vs Sentry
        var isSentry = AnsiConsole.Confirm("Is this [bold]Sentry[/] logs?", false);

        // 3) Collect S3 path parts
        var bucket = AskNonEmpty("S3 bucket (e.g. cb5c03af-...-eu-west-1-alblogs): ");
        var albId = AskNonEmpty("ALB identifier (e.g. ALB226963): ");
        var account = AskNonEmpty("Amazon account ID (12 digits): ");
        var region = AskNonEmpty("Region (e.g. eu-west-1): ");

        // 4) Timeframe (UTC) with sensible defaults
        var todayUtc = DateTime.UtcNow.Date;
        var startDefault = todayUtc;                           // 00:00
        var endDefault = todayUtc.AddHours(23).AddMinutes(55); // 23:55

        AnsiConsole.WriteLine();

        DateTime startUtc, endUtc;
        try
        {
            startUtc = SpectreDateTimePicker.PickUtc("Start (UTC)", startDefault);
            endUtc = SpectreDateTimePicker.PickUtc("End (UTC)", endDefault, minUtc: startUtc);
        }
        catch (OperationCanceledException)
        {
            AnsiConsole.MarkupLine("[yellow]Cancelled.[/]");
            ConsoleEx.Pause();
            return;
        }

        if (endUtc < startUtc)
        {
            AnsiConsole.MarkupLine("[red]End must be >= Start.[/]");
            ConsoleEx.Pause();
            return;
        }

        var prefixRoot = isSentry ? "sentry" : "standard";


        // 5) Plan
        var plan = new Table().RoundedBorder().AddColumn("Field").AddColumn("Value");
        plan.AddRow("Bucket", bucket);
        plan.AddRow("Prefix root", prefixRoot);
        plan.AddRow("ALB", albId);
        plan.AddRow("Account", account);
        plan.AddRow("Region", region);
        plan.AddRow("Start", $"{startUtc:yyyy-MM-dd HH:mm} UTC");
        plan.AddRow("End", $"{endUtc:yyyy-MM-dd HH:mm} UTC");
        plan.AddRow("Output", AppFolders.ALB);

        AnsiConsole.WriteLine();
        AnsiConsole.Write(new Panel(plan) { Header = new PanelHeader("Download plan"), Border = BoxBorder.Rounded });

        AnsiConsole.WriteLine();
        if (!AnsiConsole.Confirm("Proceed?", true))
            return;

        // 6) List, filter, download, extract
        var days = EachDayUtc(startUtc.Date, endUtc.Date).ToList();
        var keysToDownload = new List<string>();

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
                var listTask = ctx.AddTask("Listing S3 objects", maxValue: days.Count);

                foreach (var day in days)
                {
                    var dayPrefix =
                        $"{prefixRoot}/{albId}/AWSLogs/{account}/elasticloadbalancing/{region}/{day:yyyy}/{day:MM}/{day:dd}/";

                    var dayKeys = await ListObjectKeysAsync(bucket, dayPrefix, creds).ConfigureAwait(false);

                    var filtered = dayKeys
                        .Select(k => new { Key = k, Ts = TryParseAlbTimestampUtc(k) })
                        .Where(x => x.Ts.HasValue)
                        .Where(x => x.Ts!.Value >= startUtc && x.Ts!.Value <= endUtc)
                        .Select(x => x.Key)
                        .ToList();

                    keysToDownload.AddRange(filtered);

                    listTask.Increment(1);
                }

                listTask.StopTask();
            });

        if (keysToDownload.Count == 0)
        {
            AnsiConsole.WriteLine();
            AnsiConsole.MarkupLine("[yellow]No objects matched the selected timeframe.[/]");
            ConsoleEx.Pause();
            return;
        }

        AnsiConsole.WriteLine();
        AnsiConsole.MarkupLine($"Total objects to download: [bold]{keysToDownload.Count}[/]");

        // Put downloads in a subfolder per run (keeps ALB tidy)
        var runFolderName = $"ALB_{startUtc:yyyyMMdd_HHmm}Z_to_{endUtc:yyyyMMdd_HHmm}Z";
        var runFolder = Path.Combine(AppFolders.ALB, runFolderName);
        Directory.CreateDirectory(runFolder);

        int downloaded = 0, extracted = 0, failed = 0;

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
                var dlTask = ctx.AddTask("Downloading + extracting", maxValue: keysToDownload.Count);

                for (var i = 0; i < keysToDownload.Count; i++)
                {
                    var key = keysToDownload[i];
                    var fileName = Path.GetFileName(key);
                    var localGz = Path.Combine(runFolder, fileName);

                    dlTask.Description = $"Downloading: {Markup.Escape(fileName)}";

                    var ok = await AwsCpAsync(bucket, key, localGz, creds).ConfigureAwait(false);
                    if (!ok)
                    {
                        failed++;
                        dlTask.Increment(1);
                        continue;
                    }

                    downloaded++;

                    if (localGz.EndsWith(".gz", StringComparison.OrdinalIgnoreCase))
                    {
                        try
                        {
                            var localLog = localGz[..^3]; // remove ".gz"
                            await ExtractGzipAsync(localGz, localLog).ConfigureAwait(false);
                            File.Delete(localGz);
                            extracted++;
                        }
                        catch
                        {
                            failed++;
                        }
                    }

                    dlTask.Increment(1);
                }

                dlTask.StopTask();
            });

        AnsiConsole.WriteLine();
        var summary = new Table().RoundedBorder().AddColumn("Metric").AddColumn("Value");
        summary.AddRow("Downloaded", downloaded.ToString());
        summary.AddRow("Extracted", extracted.ToString());
        summary.AddRow("Failed", failed.ToString());
        summary.AddRow("Folder", runFolder);

        AnsiConsole.Write(new Panel(summary) { Header = new PanelHeader("Done"), Border = BoxBorder.Rounded });
        ConsoleEx.Pause();
    }

    // ---------- Spectre prompts ----------

    private static string AskNonEmpty(string label)
    {
        return AnsiConsole.Prompt(
            new TextPrompt<string>(Markup.Escape(label))
                .AllowEmpty()
                .Validate(s => string.IsNullOrWhiteSpace(s)
                    ? ValidationResult.Error("Value cannot be empty.")
                    : ValidationResult.Success())
        ).Trim();
    }

    private static DateTime AskUtcDateTime5Min(string label, DateTime defaultUtc, DateTime? minUtc = null)
    {
        // Date
        var date = AnsiConsole.Prompt(
            new TextPrompt<string>($"{Markup.Escape(label)} date (YYYY-MM-DD)")
                .DefaultValue(defaultUtc.ToString("yyyy-MM-dd"))
                .Validate(s => DateTime.TryParseExact(s, "yyyy-MM-dd", null,
                        System.Globalization.DateTimeStyles.None, out _)
                    ? ValidationResult.Success()
                    : ValidationResult.Error("Invalid date. Expected YYYY-MM-DD."))
        );

        // Time (5-min increments)
        var times = Build5MinTimes();
        var defaultTime = defaultUtc.ToString("HH:mm");

        var time = AnsiConsole.Prompt(
            new SelectionPrompt<string>()
                .Title($"{Markup.Escape(label)} time (UTC)")
                .PageSize(12)
                .MoreChoicesText("[grey](Move up/down to see more)[/]")
                .HighlightStyle(new Style(foreground: Color.Cyan1))
                .AddChoices(times)
        );

        // If user didn’t scroll, it won’t auto default; we can make it default-ish by placing it first
        // But Spectre SelectionPrompt doesn’t have a default selection in older versions.
        // So we keep it simple: if they press Enter immediately, it selects first item.
        // To approximate default, we rotate the list to start at defaultTime.
        // (We do that by building times with defaultTime first)
        // NOTE: Build5MinTimes() already handles default ordering when asked.
        // We'll rebuild with defaultTime at top:
        times = Build5MinTimes(defaultTime);
        time = AnsiConsole.Prompt(
            new SelectionPrompt<string>()
                .Title($"{Markup.Escape(label)} time (UTC)")
                .PageSize(12)
                .MoreChoicesText("[grey](Move up/down to see more)[/]")
                .AddChoices(times)
        );

        if (!DateTime.TryParseExact(date, "yyyy-MM-dd", null,
                System.Globalization.DateTimeStyles.None, out var d))
            d = defaultUtc.Date;

        var parts = time.Split(':');
        var hh = int.Parse(parts[0]);
        var mm = int.Parse(parts[1]);

        var dt = new DateTime(d.Year, d.Month, d.Day, hh, mm, 0, DateTimeKind.Utc);

        if (minUtc.HasValue && dt < minUtc.Value)
        {
            AnsiConsole.MarkupLine($"[yellow]{Markup.Escape(label)} adjusted to min: {minUtc.Value:yyyy-MM-dd HH:mm} UTC[/]");
            return minUtc.Value;
        }

        return dt;
    }

    private static List<string> Build5MinTimes(string? preferredFirst = null)
    {
        var list = new List<string>(288);
        for (int h = 0; h < 24; h++)
            for (int m = 0; m < 60; m += 5)
                list.Add($"{h:D2}:{m:D2}");

        if (!string.IsNullOrWhiteSpace(preferredFirst) && list.Contains(preferredFirst))
        {
            // rotate so preferredFirst appears at the top
            var idx = list.IndexOf(preferredFirst);
            if (idx > 0)
            {
                var rotated = list.Skip(idx).Concat(list.Take(idx)).ToList();
                return rotated;
            }
        }

        return list;
    }

    // ---------- Helpers (same core logic) ----------

    private static IEnumerable<DateTime> EachDayUtc(DateTime startDateUtc, DateTime endDateUtc)
    {
        for (var d = startDateUtc.Date; d <= endDateUtc.Date; d = d.AddDays(1))
            yield return DateTime.SpecifyKind(d, DateTimeKind.Utc);
    }

    private static DateTime? TryParseAlbTimestampUtc(string s3Key)
    {
        var m = AlbTimestampRegex.Match(s3Key);
        if (!m.Success) return null;

        var ymd = m.Groups[1].Value;  // YYYYMMDD
        var hm = m.Groups[2].Value;   // HHMM

        if (!int.TryParse(ymd[..4], out var year)) return null;
        if (!int.TryParse(ymd[4..6], out var month)) return null;
        if (!int.TryParse(ymd[6..8], out var day)) return null;

        if (!int.TryParse(hm[..2], out var hour)) return null;
        if (!int.TryParse(hm[2..4], out var minute)) return null;

        return new DateTime(year, month, day, hour, minute, 0, DateTimeKind.Utc);
    }

    private static string ReadMultiline()
    {
        var sb = new StringBuilder();
        while (true)
        {
            var line = Console.ReadLine();
            if (string.IsNullOrWhiteSpace(line)) break;
            sb.AppendLine(line);
        }
        return sb.ToString();
    }

    private static (bool IsValid, string? AccessKeyId, string? SecretAccessKey, string? SessionToken) ParseAwsEnvVars(string text)
    {
        string? ak = null, sk = null, st = null;

        foreach (var raw in text.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries))
        {
            var line = raw.Trim();

            if (line.StartsWith("SET ", StringComparison.OrdinalIgnoreCase)) line = line[4..].Trim();
            if (line.StartsWith("$env:", StringComparison.OrdinalIgnoreCase)) line = line[5..].Trim();

            var idx = line.IndexOf('=');
            if (idx <= 0) continue;

            var key = line[..idx].Trim();
            var val = line[(idx + 1)..].Trim().Trim('"');

            if (key.Equals("AWS_ACCESS_KEY_ID", StringComparison.OrdinalIgnoreCase)) ak = val;
            else if (key.Equals("AWS_SECRET_ACCESS_KEY", StringComparison.OrdinalIgnoreCase)) sk = val;
            else if (key.Equals("AWS_SESSION_TOKEN", StringComparison.OrdinalIgnoreCase)) st = val;
        }

        return (!string.IsNullOrWhiteSpace(ak) &&
                !string.IsNullOrWhiteSpace(sk) &&
                !string.IsNullOrWhiteSpace(st),
            ak, sk, st);
    }

    private static async Task<List<string>> ListObjectKeysAsync(
        string bucket,
        string prefix,
        (bool IsValid, string? AccessKeyId, string? SecretAccessKey, string? SessionToken) creds)
    {
        var keys = new List<string>();
        string? token = null;

        while (true)
        {
            var args = new StringBuilder();
            args.Append("s3api list-objects-v2 ");
            args.Append($"--bucket \"{bucket}\" ");
            args.Append($"--prefix \"{prefix}\" ");
            args.Append("--max-items 1000 ");
            args.Append("--output json ");

            if (!string.IsNullOrWhiteSpace(token))
                args.Append($"--starting-token \"{token}\" ");

            var (ok, stdout, stderr) = await RunAwsAsync(args.ToString(), creds).ConfigureAwait(false);
            if (!ok)
            {
                AnsiConsole.MarkupLine($"[red]list-objects-v2 failed:[/] {Markup.Escape(stderr)}");
                break;
            }

            using var doc = JsonDocument.Parse(stdout);
            if (doc.RootElement.TryGetProperty("Contents", out var contents) &&
                contents.ValueKind == JsonValueKind.Array)
            {
                foreach (var item in contents.EnumerateArray())
                {
                    if (item.TryGetProperty("Key", out var keyProp))
                    {
                        var k = keyProp.GetString();
                        if (!string.IsNullOrWhiteSpace(k))
                            keys.Add(k);
                    }
                }
            }

            token = null;
            if (doc.RootElement.TryGetProperty("NextToken", out var nextTokenProp) &&
                nextTokenProp.ValueKind == JsonValueKind.String)
            {
                token = nextTokenProp.GetString();
            }

            if (string.IsNullOrWhiteSpace(token))
                break;
        }

        return keys;
    }

    private static async Task<bool> AwsCpAsync(
        string bucket,
        string key,
        string destPath,
        (bool IsValid, string? AccessKeyId, string? SecretAccessKey, string? SessionToken) creds)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(destPath)!);

        var s3Uri = $"s3://{bucket}/{key}";
        var args = $"s3 cp \"{s3Uri}\" \"{destPath}\"";

        var (ok, _, stderr) = await RunAwsAsync(args, creds).ConfigureAwait(false);
        if (!ok)
            AnsiConsole.MarkupLine($"[red]aws cp failed:[/] {Markup.Escape(stderr)}");

        return ok;
    }

    private static async Task<(bool Ok, string StdOut, string StdErr)> RunAwsAsync(
        string arguments,
        (bool IsValid, string? AccessKeyId, string? SecretAccessKey, string? SessionToken) creds)
    {
        var psi = new ProcessStartInfo
        {
            FileName = "aws",
            Arguments = arguments,
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true
        };

        psi.Environment["AWS_ACCESS_KEY_ID"] = creds.AccessKeyId!;
        psi.Environment["AWS_SECRET_ACCESS_KEY"] = creds.SecretAccessKey!;
        psi.Environment["AWS_SESSION_TOKEN"] = creds.SessionToken!;
        psi.Environment["AWS_PAGER"] = "";

        using var proc = new Process { StartInfo = psi };

        try
        {
            proc.Start();

            var stdoutTask = proc.StandardOutput.ReadToEndAsync();
            var stderrTask = proc.StandardError.ReadToEndAsync();

            await proc.WaitForExitAsync().ConfigureAwait(false);

            var stdout = await stdoutTask.ConfigureAwait(false);
            var stderr = await stderrTask.ConfigureAwait(false);

            return (proc.ExitCode == 0, stdout, stderr);
        }
        catch (Exception ex)
        {
            return (false, "", ex.Message);
        }
    }

    private static async Task ExtractGzipAsync(string gzPath, string outPath)
    {
        using var inFile = File.OpenRead(gzPath);
        using var gzip = new GZipStream(inFile, CompressionMode.Decompress);
        using var outFile = File.Create(outPath);
        await gzip.CopyToAsync(outFile).ConfigureAwait(false);
    }
}
