using System.Reflection;
using Spectre.Console;
using LogHunter.Menus;
using LogHunter.Services;

namespace LogHunter;

internal static class Program
{
    private static volatile bool _ctrlCRequested;

    private static async Task Main(string[] args)
    {
        var version = Assembly.GetExecutingAssembly()
            .GetCustomAttribute<AssemblyInformationalVersionAttribute>()?
            .InformationalVersion
            ?? Assembly.GetExecutingAssembly().GetName().Version?.ToString()
            ?? "unknown";

        // Args
        string? rootOverride = null;

        for (var i = 0; i < args.Length; i++)
        {
            var a = args[i];

            if (a is "--version" or "-v")
            {
                Console.WriteLine(version);
                return;
            }

            if (a is "--help" or "-h" or "/?")
            {
                ShowHelp(version);
                return;
            }

            if (a == "--root")
            {
                if (i + 1 >= args.Length)
                {
                    Console.WriteLine("Missing value for --root");
                    Console.WriteLine();
                    ShowHelp(version);
                    return;
                }

                rootOverride = args[++i];
                continue;
            }

            // Unknown arg
            Console.WriteLine($"Unknown argument: {a}");
            Console.WriteLine();
            ShowHelp(version);
            return;
        }

        Console.CancelKeyPress += (_, e) =>
        {
            // Don't kill the process immediately; let the loop exit cleanly.
            e.Cancel = true;
            _ctrlCRequested = true;
        };

        try
        {
            AnsiConsole.MarkupLine($"[bold]LogHunter[/] [dim]Beta {version}[/]");

            AppFolders.Ensure();

            // Default workspace stays consistent with your current behavior (portable exe folder),
            // but can be overridden with --root.
            var root = string.IsNullOrWhiteSpace(rootOverride)
                ? AppContext.BaseDirectory
                : Path.GetFullPath(rootOverride);

            AnsiConsole.MarkupLine($"[dim]Workspace:[/] {Markup.Escape(root)}");
            AnsiConsole.MarkupLine("[dim]Tip:[/] Ctrl+C to exit");

            var session = new SessionState(root);

            IMenu? menu = new MainMenu(session);
            while (menu is not null && !_ctrlCRequested)
                menu = await menu.ShowAsync().ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            // Friendly error boundary (still useful when someone runs this in a raw terminal)
            try
            {
                AnsiConsole.MarkupLine("[red]Unhandled error[/]");
                AnsiConsole.WriteException(ex, ExceptionFormats.ShortenEverything);
            }
            catch
            {
                Console.WriteLine("Unhandled error:");
                Console.WriteLine(ex);
            }
        }
    }

    private static void ShowHelp(string version)
    {
        Console.WriteLine($"LogHunter Beta {version}");
        Console.WriteLine();
        Console.WriteLine("Usage:");
        Console.WriteLine("  LogHunter [--root <path>] [--version] [--help]");
        Console.WriteLine();
        Console.WriteLine("Options:");
        Console.WriteLine("  --root <path>   Workspace path (defaults to the exe folder)");
        Console.WriteLine("  --version, -v   Print version and exit");
        Console.WriteLine("  --help, -h      Show this help");
    }
}