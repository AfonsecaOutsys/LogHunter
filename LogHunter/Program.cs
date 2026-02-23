// Program.cs  (tidied, same behavior)
using LogHunter.Menus;
using LogHunter.Services;
using Spectre.Console;
using System.Diagnostics;
using System.IO;
using System.Reflection;
using System.Text;

namespace LogHunter;

sealed class BellDetectingWriter : TextWriter
{
    private readonly TextWriter _inner;
    public BellDetectingWriter(TextWriter inner) => _inner = inner;

    public override Encoding Encoding => _inner.Encoding;

    public override void Write(char value)
    {
        if (value == '\a') Debugger.Break();
        _inner.Write(value);
    }

    public override void Write(string? value)
    {
        if (value is not null && value.IndexOf('\a') >= 0) Debugger.Break();
        _inner.Write(value);
    }

    public override void WriteLine(string? value)
    {
        if (value is not null && value.IndexOf('\a') >= 0) Debugger.Break();
        _inner.WriteLine(value);
    }
}

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

            Console.WriteLine($"Unknown argument: {a}");
            Console.WriteLine();
            ShowHelp(version);
            return;
        }

        Console.CancelKeyPress += (_, e) =>
        {
            e.Cancel = true;
            _ctrlCRequested = true;
        };

        try
        {
            // MUST be before any AnsiConsole output
            Console.SetOut(new BellDetectingWriter(Console.Out));
            Console.SetError(new BellDetectingWriter(Console.Error));

            var root = string.IsNullOrWhiteSpace(rootOverride)
                ? AppContext.BaseDirectory
                : Path.GetFullPath(rootOverride);

            AppFolders.Ensure();

            AnsiConsole.MarkupLine($"[bold]LogHunter[/] [dim]{version}[/]");
            AnsiConsole.MarkupLine($"[dim]Workspace:[/] {Markup.Escape(root)}");
            AnsiConsole.MarkupLine("[dim]Tip:[/] Ctrl+C to exit");

            var session = new SessionState(root);

            IMenu? menu = new MainMenu(session);
            while (menu is not null && !_ctrlCRequested)
                menu = await menu.ShowAsync().ConfigureAwait(false);
        }
        catch (Exception ex)
        {
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
        Console.WriteLine($"LogHunter {version}");
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