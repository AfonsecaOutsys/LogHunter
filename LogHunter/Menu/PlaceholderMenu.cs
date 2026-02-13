using LogHunter.Services;
using LogHunter.Utils;
using Spectre.Console;

namespace LogHunter.Menus;

public sealed class PlaceholderMenu : IMenu
{
    private readonly SessionState _session;
    private readonly string _title;

    public PlaceholderMenu(SessionState session, string title)
    {
        _session = session;
        _title = title;
    }

    public Task<IMenu?> ShowAsync()
    {
        ConsoleEx.Header(_title, $"Workspace: {_session.Root}");
        AnsiConsole.MarkupLine("[yellow]Not implemented yet.[/]");
        ConsoleEx.Pause();
        return Task.FromResult<IMenu?>(new MainMenu(_session));
    }
}
