using LogHunter.Menus;
using LogHunter.Services;
using LogHunter.Utils;

namespace LogHunter.Menus;

public sealed class MainMenu : IMenu
{
    private readonly SessionState _session;

    public MainMenu(SessionState session) => _session = session;

    public Task<IMenu?> ShowAsync()
    {
        ConsoleEx.Header("LogHunter (POC)", $"Workspace: {_session.Root}");

        Console.WriteLine("  [1] ALB");
        Console.WriteLine("  [2] IIS (placeholder)");
        Console.WriteLine("  [3] Platform (placeholder)");
        Console.WriteLine("  [4] Show saved selections");
        Console.WriteLine("  [5] Export ALL saved selections");
        Console.WriteLine("  [6] Clear saved selections");
        Console.WriteLine("  [0] Exit");
        Console.WriteLine();

        var choice = ConsoleEx.Prompt("Select: ").Trim();

        switch (choice)
        {
            case "1":
                return Task.FromResult<IMenu?>(new AlbMenu(_session));

            case "2":
                return Task.FromResult<IMenu?>(new PlaceholderMenu(_session, "IIS (placeholder)"));

            case "3":
                return Task.FromResult<IMenu?>(new PlaceholderMenu(_session, "Platform (placeholder)"));

            case "4":
                ConsoleEx.Header("Saved selections");
                SelectionService.ShowSavedSelections(_session.SavedSelections);
                ConsoleEx.Pause();
                return Task.FromResult<IMenu?>(this);

            case "5":
                ConsoleEx.Header("Export saved selections");
                if (_session.SavedSelections.Count == 0)
                {
                    Console.WriteLine("(no saved selections to export)");
                    ConsoleEx.Pause();
                    return Task.FromResult<IMenu?>(this);
                }
                SelectionService.ExportAll(Path.Combine(_session.Root, "output"), _session.SavedSelections);
                ConsoleEx.Pause();
                return Task.FromResult<IMenu?>(this);

            case "6":
                ConsoleEx.Header("Clear saved selections");
                if (ConsoleEx.ReadYesNo("Clear ALL saved selections for this session?", defaultYes: false))
                    SelectionService.ClearSavedSelections(_session.SavedSelections);
                ConsoleEx.Pause();
                return Task.FromResult<IMenu?>(this);

            case "0":
                return Task.FromResult<IMenu?>(null);

            default:
                return Task.FromResult<IMenu?>(this);
        }
    }
}
