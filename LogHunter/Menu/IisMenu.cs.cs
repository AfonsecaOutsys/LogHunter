using LogHunter.Services;
using LogHunter.Utils;

namespace LogHunter.Menus;

public sealed class IisMenu : IMenu
{
    private readonly SessionState _session;

    public IisMenu(SessionState session) => _session = session;

    public async Task<IMenu?> ShowAsync(CancellationToken ct = default)
    {
        ConsoleEx.Header("IIS", $"Workspace: {_session.Root}");

        var items = new[]
        {
            new ConsoleEx.MenuItem(
                "4xx > pick suspicious IPs > pivot to 2xx/3xx",
                "Gives you a list and a IIS log filtered for suspicious IP activity that was successful on IIS, further analysing we can see if anything was compromised."
            ),
            new ConsoleEx.MenuItem("Top endpoints by latency (placeholder)", "Future: group by cs-uri-stem and rank by time-taken."),
            new ConsoleEx.MenuItem("Back", "Return to main menu.")
        };

        var selected = ConsoleEx.Menu("Select an option:", items, pageSize: 10);

        if (selected is null)
            return new MainMenu(_session); // ESC = back

        switch (selected.Value)
        {
            case 0:
                await IisOption_4xxPivot2xx3xx.RunAsync(_session.Root, ct);
                return this;

            case 1:
                await IisOption_TopEndpointsByLatency.RunAsync(_session.Root, ct);
                return this;

            case 2:
                return new MainMenu(_session);

            default:
                return this;
        }
    }
}
