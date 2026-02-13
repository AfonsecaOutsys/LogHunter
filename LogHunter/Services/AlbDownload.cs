using System.ComponentModel;
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
    // Filename contains: ..._YYYYMMDDTHHMMZ_...
    // Example: ..._20260211T0650Z_... => interval is typically 06:45->06:50 UTC
    private static readonly Regex AlbTimestampRegex =
        new(@"_(\d{8})T(\d{4})Z_", RegexOptions.Compiled | RegexOptions.CultureInvariant);

    // AWS region near end of bucket name: ...-ap-northeast-1-alblogs
    private static readonly Regex AwsRegionAtEndRegex =
        new(@"(?<region>(?:af|ap|ca|eu|me|sa|us|cn)-[a-z0-9-]+-\d)$",
            RegexOptions.Compiled | RegexOptions.CultureInvariant | RegexOptions.IgnoreCase);

    private static AwsCreds? _sessionCreds;
    private static string? _awsExePathCached;

    private static readonly JsonSerializerOptions JsonOpts = new()
    {
        WriteIndented = true
    };

    private enum AlbScope { Normal, Internal }

    private sealed record AwsCreds(string AccessKeyId, string SecretAccessKey, string SessionToken);

    private sealed class AlbConfig
    {
        public string Name { get; set; } = "";       // file name / selection label
        public string Bucket { get; set; } = "";
        public string AlbId { get; set; } = "";      // base id e.g. ALB226963
        public AlbScope Scope { get; set; } = AlbScope.Normal; // Normal or Internal
        public string AccountId { get; set; } = "";
        public string Region { get; set; } = "";
        public bool IsSentry { get; set; }           // standard vs sentry prefix root
        public DateTime LastUsedUtc { get; set; } = DateTime.UtcNow;
    }

    public static async Task RunAsync()
    {
        AppFolders.Ensure();
        EnsureConfigsFolder();

        ConsoleEx.Header("ALB - Download logs", $"Destination: {AppFolders.ALB}");

        var awsExe = ResolveAwsExePath();
        if (string.IsNullOrWhiteSpace(awsExe))
        {
            AnsiConsole.MarkupLine("[red]Couldn't find aws.exe.[/]");
            AnsiConsole.MarkupLine("Make sure AWS CLI v2 is installed and available on PATH (try: [grey]where aws[/]).");
            ConsoleEx.Pause();
            return;
        }

        // --- Choose config flow ---
        AlbConfig? cfg;

        var mode = AnsiConsole.Prompt(
            new SelectionPrompt<string>()
                .Title("Download ALB logs: choose an option")
                .AddChoices("New configuration", "Previously saved configuration", "Cancel"));

        if (mode == "Cancel")
            return;

        if (mode == "Previously saved configuration")
        {
            cfg = PickExistingConfig();
            if (cfg is null)
            {
                AnsiConsole.MarkupLine("[yellow]No saved configurations found (or selection cancelled).[/]");
                ConsoleEx.Pause();
                return;
            }

            AnsiConsole.MarkupLineInterpolated($"[grey]Using saved config:[/] [white]{Markup.Escape(cfg.Name)}[/]");
        }
        else
        {
            cfg = CreateNewConfig();
            if (cfg is null)
            {
                AnsiConsole.MarkupLine("[yellow]Cancelled.[/]");
                ConsoleEx.Pause();
                return;
            }
        }

        // --- Credentials: ask once per session ---
        var creds = await GetSessionCredsAsync().ConfigureAwait(false);
        if (creds is null)
            return;

        // --- Timeframe (UTC) ---
        var todayUtc = DateTime.UtcNow.Date;
        var startDefault = todayUtc;                           // 00:00
        var endDefault = todayUtc.AddHours(23).AddMinutes(55); // 23:55

        DateTime startUtc, endUtc;
        try
        {
            AnsiConsole.WriteLine();
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

        // Persist last-used timestamp (no tokens saved)
        try { cfg.LastUsedUtc = DateTime.UtcNow; SaveConfig(cfg); } catch { /* non-fatal */ }

        // Build prefix root + ALB key (THIS IS THE IMPORTANT PART)
        var prefixRoot = cfg.IsSentry ? "sentry" : "standard";
        var albKey = cfg.Scope == AlbScope.Internal ? $"{cfg.AlbId}-internal" : cfg.AlbId;

        // --- Plan ---
        AnsiConsole.WriteLine();
        var plan = new Table().RoundedBorder().Title("[grey]Download plan[/]")
            .AddColumn("Field").AddColumn("Value");

        plan.AddRow("aws.exe", Markup.Escape(awsExe));
        plan.AddRow("Config", Markup.Escape(cfg.Name));
        plan.AddRow("Bucket", Markup.Escape(cfg.Bucket));
        plan.AddRow("Prefix root", Markup.Escape(prefixRoot));
        plan.AddRow("ALB key", Markup.Escape(albKey));
        plan.AddRow("Account", Markup.Escape(cfg.AccountId));
        plan.AddRow("Region", Markup.Escape(cfg.Region));
        plan.AddRow("Start", $"{startUtc:yyyy-MM-dd HH:mm} UTC");
        plan.AddRow("End", $"{endUtc:yyyy-MM-dd HH:mm} UTC");
        plan.AddRow("Output", Markup.Escape(AppFolders.ALB));

        AnsiConsole.Write(plan);
        AnsiConsole.WriteLine();

        if (!ConsoleEx.ReadYesNo("Proceed? (y/n): "))
            return;

        // --- Run folder under ALB ---
        var runFolderName = $"{cfg.Name}_{startUtc:yyyyMMdd_HHmm}Z_to_{endUtc:yyyyMMdd_HHmm}Z";
        runFolderName = SanitizeFileName(runFolderName);
        var runFolder = Path.Combine(AppFolders.ALB, runFolderName);
        Directory.CreateDirectory(runFolder);

        // --- Sync full days (fast) ---
        var days = EachDayUtc(startUtc.Date, endUtc.Date).ToList();
        var daySyncFailures = 0;

        AnsiConsole.WriteLine();
        AnsiConsole.MarkupLine($"[grey]Downloading full day prefixes ({days.Count} day(s)) using aws s3 sync...[/]");
        AnsiConsole.WriteLine();

        foreach (var day in days)
        {
            var dayPrefix =
                $"{prefixRoot}/{albKey}/AWSLogs/{cfg.AccountId}/elasticloadbalancing/{cfg.Region}/{day:yyyy}/{day:MM}/{day:dd}/";

            var s3Uri = $"s3://{cfg.Bucket}/{dayPrefix}";
            var title = $"Downloading day {day:yyyy-MM-dd}";

            var ok = await AnsiConsole.Status()
                .Spinner(Spinner.Known.Dots)
                .SpinnerStyle(Style.Parse("grey"))
                .StartAsync(title, async _ =>
                {
                    return await AwsSyncPrefixAsync(
                        awsExePath: awsExe,
                        s3Uri: s3Uri,
                        destFolder: runFolder,
                        creds: creds).ConfigureAwait(false);
                });

            if (ok)
                AnsiConsole.MarkupLine($"[green]OK[/] {day:yyyy-MM-dd}");
            else
            {
                daySyncFailures++;
                AnsiConsole.MarkupLine($"[red]FAILED[/] {day:yyyy-MM-dd}");
            }
        }

        // Enumerate downloaded .gz
        var allGz = Directory.Exists(runFolder)
            ? Directory.EnumerateFiles(runFolder, "*.gz", SearchOption.AllDirectories).ToList()
            : new List<string>();

        if (allGz.Count == 0)
        {
            AnsiConsole.MarkupLine("[yellow]No .gz files were downloaded.[/]");
            Console.WriteLine($"Day sync failures: {daySyncFailures}");
            Console.WriteLine($"Folder: {runFolder}");
            ConsoleEx.Pause();
            return;
        }

        // --- Prune outside timeframe (based on overlap of [stamp-5min, stamp]) ---
        var kept = 0;
        var deleted = 0;
        var unknown = 0;

        AnsiConsole.WriteLine();
        AnsiConsole.MarkupLine($"[grey]Pruning out-of-range .gz files (downloaded: {allGz.Count})...[/]");

        await AnsiConsole.Status()
            .Spinner(Spinner.Known.Dots)
            .SpinnerStyle(Style.Parse("grey"))
            .StartAsync("Pruning (delete outside timeframe)", async _ =>
            {
                foreach (var gz in allGz)
                {
                    var stamp = TryParseAlbTimestampUtc(Path.GetFileName(gz));
                    if (!stamp.HasValue)
                    {
                        unknown++;
                        kept++;
                        continue;
                    }

                    var intervalEnd = stamp.Value;
                    var intervalStart = intervalEnd.AddMinutes(-5);

                    var overlaps = intervalStart <= endUtc && intervalEnd >= startUtc;

                    if (!overlaps)
                    {
                        try
                        {
                            File.Delete(gz);
                            deleted++;
                        }
                        catch
                        {
                            kept++;
                        }
                    }
                    else
                    {
                        kept++;
                    }
                }

                await Task.CompletedTask;
            });

        var gzFiles = Directory.EnumerateFiles(runFolder, "*.gz", SearchOption.AllDirectories).ToList();

        if (gzFiles.Count == 0)
        {
            AnsiConsole.MarkupLine("[yellow]After pruning, no .gz files remain in the selected timeframe.[/]");
            Console.WriteLine($"Downloaded: {allGz.Count}");
            Console.WriteLine($"Deleted:    {deleted}");
            Console.WriteLine($"Unknown ts: {unknown} (kept)");
            Console.WriteLine($"Folder:     {runFolder}");
            ConsoleEx.Pause();
            return;
        }

        // --- Extract after all downloads ---
        var extracted = 0;
        var extractFailed = 0;

        AnsiConsole.WriteLine();
        AnsiConsole.MarkupLine($"[grey]Extracting {gzFiles.Count} file(s)...[/]");

        await AnsiConsole.Status()
            .Spinner(Spinner.Known.Dots)
            .SpinnerStyle(Style.Parse("grey"))
            .StartAsync("Extracting .gz -> .log", async _ =>
            {
                foreach (var gzPath in gzFiles)
                {
                    try
                    {
                        var outPath = gzPath[..^3]; // remove ".gz"
                        await ExtractGzipAsync(gzPath, outPath).ConfigureAwait(false);
                        File.Delete(gzPath);
                        extracted++;
                    }
                    catch
                    {
                        extractFailed++;
                    }
                }
            });

        Console.WriteLine();
        Console.WriteLine("Done.");
        Console.WriteLine($"  Config name:          {cfg.Name}");
        Console.WriteLine($"  Prefix root:          {prefixRoot}");
        Console.WriteLine($"  ALB key:              {albKey}");
        Console.WriteLine($"  Days requested:       {days.Count}");
        Console.WriteLine($"  Day sync failures:    {daySyncFailures}");
        Console.WriteLine($"  Downloaded (.gz):     {allGz.Count}");
        Console.WriteLine($"  Pruned (deleted):     {deleted}");
        Console.WriteLine($"  Unknown timestamp:    {unknown} (kept)");
        Console.WriteLine($"  Kept for extraction:  {gzFiles.Count}");
        Console.WriteLine($"  Extracted (.log):     {extracted}");
        Console.WriteLine($"  Extract failed:       {extractFailed}");
        Console.WriteLine($"  Folder:               {runFolder}");
        ConsoleEx.Pause();
    }

    // =========================
    // Config Flow
    // =========================

    private static void EnsureConfigsFolder()
        => Directory.CreateDirectory(GetConfigsFolder());

    private static string GetConfigsFolder()
        => Path.Combine(AppFolders.ALB, "configs");

    private static AlbConfig? PickExistingConfig()
    {
        EnsureConfigsFolder();

        var files = Directory.EnumerateFiles(GetConfigsFolder(), "*.json", SearchOption.TopDirectoryOnly)
            .OrderByDescending(File.GetLastWriteTimeUtc)
            .ToList();

        if (files.Count == 0)
            return null;

        var configs = new List<AlbConfig>();
        foreach (var f in files)
        {
            try
            {
                var json = File.ReadAllText(f, Encoding.UTF8);
                var c = JsonSerializer.Deserialize<AlbConfig>(json, JsonOpts);
                if (c is not null && !string.IsNullOrWhiteSpace(c.Name))
                    configs.Add(c);
            }
            catch { }
        }

        if (configs.Count == 0)
            return null;

        var choice = AnsiConsole.Prompt(
            new SelectionPrompt<AlbConfig>()
                .Title("Select a saved configuration")
                .PageSize(12)
                .UseConverter(c =>
                {
                    var scope = c.Scope == AlbScope.Internal ? "Internal" : "Normal";
                    var sentry = c.IsSentry ? "Sentry" : "Standard";
                    return $"{c.Name}  |  {c.Region}  |  {scope}  |  {sentry}  |  {c.AlbId}";
                })
                .AddChoices(configs)
        );

        return choice;
    }

    private static AlbConfig? CreateNewConfig()
    {
        EnsureConfigsFolder();

        // Internal vs Normal (new requirement - affects ALB key with "-internal")
        var scopeStr = AnsiConsole.Prompt(
            new SelectionPrompt<string>()
                .Title("ALB type?")
                .AddChoices("1 - Normal", "2 - Internal"));

        var scope = scopeStr.StartsWith("2") ? AlbScope.Internal : AlbScope.Normal;

        // Sentry?
        var isSentry = ConsoleEx.ReadYesNo("Is this Sentry logs? (y/n): ");

        // Inputs
        var bucket = ConsoleEx.Prompt("S3 bucket (e.g. ...-eu-west-1-alblogs): ").Trim();
        var albId = ConsoleEx.Prompt("ALB identifier (e.g. ALB226963): ").Trim();
        var account = ConsoleEx.Prompt("Amazon account ID (12 digits): ").Trim();

        if (string.IsNullOrWhiteSpace(bucket) ||
            string.IsNullOrWhiteSpace(albId) ||
            string.IsNullOrWhiteSpace(account))
        {
            AnsiConsole.MarkupLine("[red]Missing required inputs.[/]");
            return null;
        }

        // Derive region from bucket
        var derivedRegion = TryDeriveRegionFromBucket(bucket);
        string region;

        if (!string.IsNullOrWhiteSpace(derivedRegion))
        {
            AnsiConsole.MarkupLineInterpolated($"[grey]Derived region from bucket:[/] [white]{Markup.Escape(derivedRegion)}[/]");
            var use = ConsoleEx.ReadYesNo("Use derived region? (y/n): ");
            region = use ? derivedRegion! : ConsoleEx.Prompt("Region (e.g. eu-west-1): ").Trim();
        }
        else
        {
            region = ConsoleEx.Prompt("Region (e.g. eu-west-1): ").Trim();
        }

        if (string.IsNullOrWhiteSpace(region))
        {
            AnsiConsole.MarkupLine("[red]Region is required.[/]");
            return null;
        }

        // Config name (default: ALB id (+ internal suffix if internal))
        var defaultName = scope == AlbScope.Internal ? $"{albId}-internal" : albId;
        var name = ConsoleEx.Prompt($"Config name (default: {defaultName}): ").Trim();
        if (string.IsNullOrWhiteSpace(name))
            name = defaultName;

        name = SanitizeFileName(name);

        var cfgPath = GetConfigPath(name);
        if (File.Exists(cfgPath))
        {
            AnsiConsole.MarkupLineInterpolated($"[yellow]A config named '{Markup.Escape(name)}' already exists.[/]");
            if (!ConsoleEx.ReadYesNo("Overwrite? (y/n): ", defaultYes: false))
                return null;
        }

        var cfg = new AlbConfig
        {
            Name = name,
            Bucket = bucket,
            AlbId = albId,
            Scope = scope,
            AccountId = account,
            Region = region,
            IsSentry = isSentry,
            LastUsedUtc = DateTime.UtcNow
        };

        SaveConfig(cfg);

        AnsiConsole.MarkupLineInterpolated($"[green]Saved config:[/] {Markup.Escape(cfg.Name)}");
        return cfg;
    }

    private static void SaveConfig(AlbConfig cfg)
    {
        EnsureConfigsFolder();
        cfg.LastUsedUtc = DateTime.UtcNow;
        var json = JsonSerializer.Serialize(cfg, JsonOpts);
        File.WriteAllText(GetConfigPath(cfg.Name), json, Encoding.UTF8);
    }

    private static string GetConfigPath(string name)
        => Path.Combine(GetConfigsFolder(), $"{SanitizeFileName(name)}.json");

    private static string SanitizeFileName(string s)
    {
        if (string.IsNullOrWhiteSpace(s)) return "config";
        foreach (var c in Path.GetInvalidFileNameChars())
            s = s.Replace(c, '_');
        return s.Trim();
    }

    private static string? TryDeriveRegionFromBucket(string bucket)
    {
        if (string.IsNullOrWhiteSpace(bucket)) return null;

        var b = bucket.Trim();
        if (b.EndsWith("-alblogs", StringComparison.OrdinalIgnoreCase))
            b = b[..^"-alblogs".Length];

        var m = AwsRegionAtEndRegex.Match(b);
        if (!m.Success) return null;

        return m.Groups["region"].Value;
    }

    // =========================
    // Credentials (per session)
    // =========================

    private static async Task<AwsCreds?> GetSessionCredsAsync()
    {
        if (_sessionCreds is not null)
        {
            AnsiConsole.MarkupLine("[grey]AWS session credentials already set for this run.[/]");
            if (ConsoleEx.ReadYesNo("Reuse them? (y/n): ", defaultYes: true))
                return _sessionCreds;
        }

        Console.WriteLine();
        Console.WriteLine("Paste the 3 AWS env lines (AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY / AWS_SESSION_TOKEN).");
        Console.WriteLine("Finish by entering an empty line.");
        Console.WriteLine();

        var pasted = ReadMultiline();
        var parsed = ParseAwsEnvVars(pasted);

        if (!parsed.IsValid ||
            string.IsNullOrWhiteSpace(parsed.AccessKeyId) ||
            string.IsNullOrWhiteSpace(parsed.SecretAccessKey) ||
            string.IsNullOrWhiteSpace(parsed.SessionToken))
        {
            Console.WriteLine();
            Console.WriteLine("Couldn't parse credentials. Expected lines like:");
            Console.WriteLine("  SET AWS_ACCESS_KEY_ID=...");
            Console.WriteLine("  SET AWS_SECRET_ACCESS_KEY=...");
            Console.WriteLine("  SET AWS_SESSION_TOKEN=...");
            Console.WriteLine();
            ConsoleEx.Pause();
            return null;
        }

        _sessionCreds = new AwsCreds(parsed.AccessKeyId!, parsed.SecretAccessKey!, parsed.SessionToken!);
        await Task.CompletedTask;
        return _sessionCreds;
    }

    // =========================
    // AWS Execution (fast path)
    // =========================

    private static bool AwsExists(string path)
        => !string.IsNullOrWhiteSpace(path) && File.Exists(path);

    private static string? ResolveAwsExePath()
    {
        if (!string.IsNullOrWhiteSpace(_awsExePathCached))
        {
            if (_awsExePathCached == "aws") return _awsExePathCached;
            if (AwsExists(_awsExePathCached)) return _awsExePathCached;
        }

        // 1) Try "aws" from PATH
        if (CanStartAwsFromPath())
        {
            _awsExePathCached = "aws";
            return _awsExePathCached;
        }

        // 2) where aws
        var fromWhere = TryGetAwsFromWhere();
        if (AwsExists(fromWhere))
        {
            _awsExePathCached = fromWhere;
            return _awsExePathCached;
        }

        // 3) common paths
        var p1 = @"C:\Program Files\Amazon\AWSCLIV2\aws.exe";
        if (AwsExists(p1)) { _awsExePathCached = p1; return _awsExePathCached; }

        var p2 = @"C:\Program Files (x86)\Amazon\AWSCLIV2\aws.exe";
        if (AwsExists(p2)) { _awsExePathCached = p2; return _awsExePathCached; }

        return null;
    }

    private static bool CanStartAwsFromPath()
    {
        try
        {
            using var p = new Process
            {
                StartInfo = new ProcessStartInfo
                {
                    FileName = "aws",
                    Arguments = "--version",
                    UseShellExecute = false,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    CreateNoWindow = true,
                    WorkingDirectory = Directory.GetCurrentDirectory()
                }
            };

            p.Start();
            p.WaitForExit(3000);
            return p.ExitCode == 0;
        }
        catch
        {
            return false;
        }
    }

    private static string? TryGetAwsFromWhere()
    {
        try
        {
            using var p = new Process
            {
                StartInfo = new ProcessStartInfo
                {
                    FileName = "where",
                    Arguments = "aws",
                    UseShellExecute = false,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    CreateNoWindow = true,
                    WorkingDirectory = Directory.GetCurrentDirectory()
                }
            };

            p.Start();
            var stdout = p.StandardOutput.ReadToEnd();
            p.WaitForExit(3000);

            if (p.ExitCode != 0) return null;

            foreach (var line in stdout.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries))
            {
                var trimmed = line.Trim();
                if (!string.IsNullOrWhiteSpace(trimmed))
                    return trimmed;
            }

            return null;
        }
        catch
        {
            return null;
        }
    }

    private static async Task<bool> AwsSyncPrefixAsync(
        string awsExePath,
        string s3Uri,
        string destFolder,
        AwsCreds creds)
    {
        Directory.CreateDirectory(destFolder);

        // Quiet + fast
        var args =
            $"s3 sync \"{s3Uri}\" \"{destFolder}\" --exclude \"*\" --include \"*.gz\" --no-progress --only-show-errors";

        var psi = new ProcessStartInfo
        {
            FileName = awsExePath,
            Arguments = args,
            UseShellExecute = false,
            RedirectStandardOutput = false,
            RedirectStandardError = false,
            CreateNoWindow = true,
            WorkingDirectory = Directory.GetCurrentDirectory()
        };

        psi.Environment["AWS_ACCESS_KEY_ID"] = creds.AccessKeyId;
        psi.Environment["AWS_SECRET_ACCESS_KEY"] = creds.SecretAccessKey;
        psi.Environment["AWS_SESSION_TOKEN"] = creds.SessionToken;
        psi.Environment["AWS_PAGER"] = "";
        psi.Environment["AWS_EC2_METADATA_DISABLED"] = "true";

        try
        {
            using var proc = new Process { StartInfo = psi };
            proc.Start();
            await proc.WaitForExitAsync().ConfigureAwait(false);

            if (proc.ExitCode == 0)
                return true;

            // If it failed, rerun capturing stderr for visibility
            var (ok2, _, err2) = await RunAwsCapturedAsync(awsExePath, args, creds).ConfigureAwait(false);
            if (!ok2 && !string.IsNullOrWhiteSpace(err2))
                AnsiConsole.MarkupLineInterpolated($"[red]aws sync error:[/] {new Markup(Markup.Escape(err2.Trim()))}");

            return false;
        }
        catch (Win32Exception ex) when (ex.NativeErrorCode == 2)
        {
            AnsiConsole.MarkupLine("[red]aws.exe not found when starting process.[/]");
            return false;
        }
        catch (Exception ex)
        {
            AnsiConsole.MarkupLineInterpolated($"[red]Failed to run aws sync:[/] {new Markup(Markup.Escape(ex.Message))}");
            return false;
        }
    }

    private static async Task<(bool Ok, string StdOut, string StdErr)> RunAwsCapturedAsync(
        string awsExePath,
        string arguments,
        AwsCreds creds)
    {
        var psi = new ProcessStartInfo
        {
            FileName = awsExePath,
            Arguments = arguments,
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true,
            WorkingDirectory = Directory.GetCurrentDirectory()
        };

        psi.Environment["AWS_ACCESS_KEY_ID"] = creds.AccessKeyId;
        psi.Environment["AWS_SECRET_ACCESS_KEY"] = creds.SecretAccessKey;
        psi.Environment["AWS_SESSION_TOKEN"] = creds.SessionToken;
        psi.Environment["AWS_PAGER"] = "";
        psi.Environment["AWS_EC2_METADATA_DISABLED"] = "true";

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

    // =========================
    // Helpers
    // =========================

    private static IEnumerable<DateTime> EachDayUtc(DateTime startDateUtc, DateTime endDateUtc)
    {
        for (var d = startDateUtc.Date; d <= endDateUtc.Date; d = d.AddDays(1))
            yield return DateTime.SpecifyKind(d, DateTimeKind.Utc);
    }

    private static DateTime? TryParseAlbTimestampUtc(string fileNameOrKey)
    {
        var m = AlbTimestampRegex.Match(fileNameOrKey);
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

    private static async Task ExtractGzipAsync(string gzPath, string outPath)
    {
        using var inFile = File.OpenRead(gzPath);
        using var gzip = new GZipStream(inFile, CompressionMode.Decompress);
        using var outFile = File.Create(outPath);
        await gzip.CopyToAsync(outFile).ConfigureAwait(false);
    }
}
