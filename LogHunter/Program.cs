using LogHunter.Menus;
using LogHunter.Services;

namespace LogHunter;

internal static class Program
{
    private static async Task Main()
    {
        // Create required folders in the working directory on startup
        AppFolders.Ensure();

        var root = AppContext.BaseDirectory;
        var session = new SessionState(root);

        IMenu? menu = new MainMenu(session);

        while (menu is not null)
            menu = await menu.ShowAsync().ConfigureAwait(false);
    }
}
