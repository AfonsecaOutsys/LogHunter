using LogHunter.Services;
using LogHunter.Utils;

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

    public Task<IMenu?> ShowAsync(CancellationToken ct = default)
    {
        ConsoleEx.Header(_title, "Not implemented yet.");
        ConsoleEx.Pause();
        return Task.FromResult<IMenu?>(new MainMenu(_session));
    }
}
