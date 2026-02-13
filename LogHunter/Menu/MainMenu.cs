using LogHunter.Services;
using LogHunter.Utils;
using Spectre.Console;

namespace LogHunter.Menus;

public sealed class MainMenu : IMenu
{
    private readonly SessionState _session;

    public MainMenu(SessionState session) => _session = session;

    public Task<IMenu?> ShowAsync()
    {
        ConsoleEx.Header("LogHunter (POC)", $"Workspace: {_session.Root}");

        var choice = AnsiConsole.Prompt(
            new SelectionPrompt<string>()
                .Title("Select an option:")
                .PageSize(10)
                .AddChoices(new[]
                {
                    "1 - ALB",
                    "2 - IIS (placeholder)",
                    "3 - Platform (placeholder)",
                    "4 - Show saved selections",
                    "5 - Export ALL saved selections",
                    "6 - Clear saved selections",
                    "0 - Exit"
                })
        );

        switch (choice[0]) // first char is the numeric option
        {
            case '1':
                return Task.FromResult<IMenu?>(new AlbMenu(_session));

            case '2':
                return Task.FromResult<IMenu?>(new PlaceholderMenu(_session, "IIS (placeholder)"));

            case '3':
                return Task.FromResult<IMenu?>(new PlaceholderMenu(_session, "Platform (placeholder)"));

            case '4':
                ConsoleEx.Header("Saved selections");
                SelectionService.ShowSavedSelections(_session.SavedSelections);
                ConsoleEx.Pause();
                return Task.FromResult<IMenu?>(this);

            case '5':
                ConsoleEx.Header("Export saved selections");
                if (_session.SavedSelections.Count == 0)
                {
                    AnsiConsole.MarkupLine("[grey](no saved selections to export)[/]");
                    ConsoleEx.Pause();
                    return Task.FromResult<IMenu?>(this);
                }

                SelectionService.ExportAll(Path.Combine(_session.Root, "output"), _session.SavedSelections);
                ConsoleEx.Pause();
                return Task.FromResult<IMenu?>(this);

            case '6':
                ConsoleEx.Header("Clear saved selections");
                if (ConsoleEx.ReadYesNo("Clear ALL saved selections for this session?", defaultYes: false))
                    SelectionService.ClearSavedSelections(_session.SavedSelections);
                ConsoleEx.Pause();
                return Task.FromResult<IMenu?>(this);

            case '0':
                return Task.FromResult<IMenu?>(null);

            default:
                return Task.FromResult<IMenu?>(this);
        }
    }
}
