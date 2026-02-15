using LogHunter.Services;
using LogHunter.Utils;
using Spectre.Console;

namespace LogHunter.Menus;

public sealed class MainMenu : IMenu
{
    private readonly SessionState _session;

    public MainMenu(SessionState session) => _session = session;

    public Task<IMenu?> ShowAsync(CancellationToken ct = default)
    {
        ConsoleEx.Header("LogHunter (POC)", $"Workspace: {_session.Root}");

        var savedCount = _session.SavedSelections.Count;

        // Hints are placeholders; you can refine them later.
        var items = new[]
        {
            new ConsoleEx.MenuItem("ALB", "AWS Application Load Balancer log tools.\n(Placeholder hint)"),
            new ConsoleEx.MenuItem("IIS (placeholder)", "Future: IIS log analysis.\n(Placeholder hint)"),
            new ConsoleEx.MenuItem("Platform (placeholder)", "Future: OutSystems platform log analysis.\n(Placeholder hint)"),
            new ConsoleEx.MenuItem($"Show saved selections ({savedCount})", "View items saved during this session.\n(Placeholder hint)"),
            new ConsoleEx.MenuItem($"Export ALL saved selections ({savedCount})", "Export all saved selections to CSV under /output.\n(Placeholder hint)"),
            new ConsoleEx.MenuItem($"Clear saved selections ({savedCount})", "Clear all saved selections for this session.\n(Placeholder hint)"),
            new ConsoleEx.MenuItem("Exit", "Quit LogHunter.")
        };

        var selected = ConsoleEx.Menu("Select an option:", items, pageSize: 10);

        // Esc = exit (main menu)
        if (selected is null)
            return Task.FromResult<IMenu?>(null);

        switch (selected.Value)
        {
            case 0:
                return Task.FromResult<IMenu?>(new AlbMenu(_session));

            case 1:
                return Task.FromResult<IMenu?>(new PlaceholderMenu(_session, "IIS (placeholder)"));

            case 2:
                return Task.FromResult<IMenu?>(new PlaceholderMenu(_session, "Platform (placeholder)"));

            case 3:
                ConsoleEx.Header("Saved selections");
                if (savedCount == 0)
                    AnsiConsole.MarkupLine("[grey](no saved selections)[/]");
                else
                    SelectionService.ShowSavedSelections(_session.SavedSelections);

                ConsoleEx.Pause();
                return Task.FromResult<IMenu?>(this);

            case 4:
                ConsoleEx.Header("Export saved selections");
                if (savedCount == 0)
                {
                    AnsiConsole.MarkupLine("[grey](no saved selections to export)[/]");
                    ConsoleEx.Pause();
                    return Task.FromResult<IMenu?>(this);
                }

                var outDir = Path.Combine(_session.Root, "output");
                SelectionService.ExportAll(outDir, _session.SavedSelections);

                AnsiConsole.MarkupLine($"[green]Export complete[/]");
                AnsiConsole.MarkupLine($"[dim]Output:[/] {Markup.Escape(outDir)}");

                ConsoleEx.Pause();
                return Task.FromResult<IMenu?>(this);

            case 5:
                ConsoleEx.Header("Clear saved selections");
                if (savedCount == 0)
                {
                    AnsiConsole.MarkupLine("[grey](no saved selections to clear)[/]");
                    ConsoleEx.Pause();
                    return Task.FromResult<IMenu?>(this);
                }

                if (ConsoleEx.ReadYesNo("Clear ALL saved selections for this session?", defaultYes: false))
                {
                    SelectionService.ClearSavedSelections(_session.SavedSelections);
                    AnsiConsole.MarkupLine("[green]Cleared[/]");
                }
                else
                {
                    AnsiConsole.MarkupLine("[grey](cancelled)[/]");
                }

                ConsoleEx.Pause();
                return Task.FromResult<IMenu?>(this);

            case 6:
                return Task.FromResult<IMenu?>(null);

            default:
                return Task.FromResult<IMenu?>(this);
        }
    }
}
