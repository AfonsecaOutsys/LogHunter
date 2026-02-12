using LogHunter.Services;
using LogHunter.Utils;

namespace LogHunter.Menus;

public sealed class AlbMenu : IMenu
{
    private readonly SessionState _session;

    public AlbMenu(SessionState session) => _session = session;

    public async Task<IMenu?> ShowAsync()
    {
        ConsoleEx.Header("ALB Menu", $"Workspace: {_session.Root}");

        Console.WriteLine("  [1] (placeholder - download logs later)");
        Console.WriteLine("  [2] Top IPs for endpoint/path fragment");
        Console.WriteLine("  [3] Top 50 IPs overall");
        Console.WriteLine("  [4] Top 50 IPs by URI (no query)");
        Console.WriteLine("  [5] Requests (no query) ordered by AVG duration filtered by target");
        Console.WriteLine("  [6] Track requests per IP per 5 minutes (chart)");
        Console.WriteLine("  [7] WAF blocked summary + Top 50 blocked requests");
        Console.WriteLine("  [0] Back");
        Console.WriteLine();

        var choice = ConsoleEx.Prompt("Select: ").Trim();

        switch (choice)
        {
            case "1":
                ConsoleEx.Header("ALB - Download logs (placeholder)");
                Console.WriteLine("Not implemented yet.");
                ConsoleEx.Pause();
                return this;

            case "2":
                await AlbOptions.TopIpsForEndpointAsync(_session.Root, _session.SavedSelections).ConfigureAwait(false);
                return this;

            case "3":
                await AlbOptions.Top50IpsOverallAsync(_session.Root).ConfigureAwait(false);
                return this;

            case "4":
                await AlbOptions.Top50IpUriNoQueryAsync(_session.Root).ConfigureAwait(false);
                return this;

            case "5":
                await AlbOptions.AvgDurationByTargetNoQueryAsync(_session.Root).ConfigureAwait(false);
                return this;

            case "6":
                await AlbOptions.TrackRequestsPerIpPer5MinAsync(_session.Root).ConfigureAwait(false);
                return this;

            case "7":
                await AlbOptions.WafBlockedSummaryAsync(_session.Root).ConfigureAwait(false);
                return this;

            case "0":
                return new MainMenu(_session);

            default:
                return this;
        }
    }
}
