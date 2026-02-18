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

        var savedBurstIps = _session.IisBurstIps.Count;

        var items = new[]
        {
            new ConsoleEx.MenuItem(
                "4xx → pick suspicious IPs → pivot to 2xx/3xx",
                "Scan 4xx, show Top 15 IPs, select suspicious, then export + summarize their 2xx/3xx hits."
            ),
            new ConsoleEx.MenuItem(
                $"Find Bursts Patterns (saved IPs: {savedBurstIps})",
                "Detect bursty request patterns per IP using time buckets (rate/enum/error heuristics)."
            ),
            new ConsoleEx.MenuItem(
                "Top endpoints by latency (placeholder)",
                "Future: group by cs-uri-stem and rank by time-taken."
            ),
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
                await IisOption_FindBurstPatterns.RunAsync(_session, ct);
                return this;

            case 2:
                await IisOption_TopEndpointsByLatency.RunAsync(_session.Root, ct);
                return this;

            case 3:
                return new MainMenu(_session);

            default:
                return this;
        }
    }
}
