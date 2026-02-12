using LogHunter.Menu;
using LogHunter.Menus;
using LogHunter.Services;

namespace LogHunter;

internal static class Program
{
    private static async Task Main()
    {
        var root = AppContext.BaseDirectory;
        var session = new SessionState(root);

        IMenu? menu = new MainMenu(session);

        while (menu is not null)
            menu = await menu.ShowAsync().ConfigureAwait(false);
    }
}