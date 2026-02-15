using LogHunter.Services;
using LogHunter.Utils;

namespace LogHunter.Menus;

public sealed class AlbMenu : IMenu
{
    private readonly SessionState _session;

    public AlbMenu(SessionState session) => _session = session;

    public async Task<IMenu?> ShowAsync(CancellationToken ct = default)
    {
        ConsoleEx.Header("ALB Menu", $"Workspace: {_session.Root}");

        // Hints are placeholders; you can refine them later.
        var items = new[]
        {
            new ConsoleEx.MenuItem("Download ALB logs", "Downloads ALB logs from S3 into the workspace.\n(Placeholder hint)"),
            new ConsoleEx.MenuItem("Top IPs for endpoint/path fragment", "Counts IPs hitting a given endpoint/path fragment.\n(Placeholder hint)"),
            new ConsoleEx.MenuItem("Top 50 IPs overall", "Scans logs and returns the top 50 client IPs.\n(Placeholder hint)"),
            new ConsoleEx.MenuItem("Top 50 IPs by URI (no query)", "Top URIs by IP, with query strings removed.\n(Placeholder hint)"),
            new ConsoleEx.MenuItem("Requests (no query) ordered by AVG duration filtered by target", "Finds slow requests for a given target host.\n(Placeholder hint)"),
            new ConsoleEx.MenuItem("Track requests per IP per 5 minutes (chart)", "Builds 5-minute time series per IP and generates outputs.\n(Placeholder hint)"),
            new ConsoleEx.MenuItem("WAF blocked summary + Top 50 blocked requests", "Summarizes WAF-blocked traffic and top blocked requests.\n(Placeholder hint)"),
            new ConsoleEx.MenuItem("WAF blocked over time (blocks/min) (chart)", "Charts blocked requests per minute.\nUses the same definition as option 7.\n(Placeholder hint)"),
            new ConsoleEx.MenuItem("Back", "Return to the previous menu.")
        };

        var selected = ConsoleEx.Menu("Select an option:", items, pageSize: 12);

        // Esc = back
        if (selected is null)
            return new MainMenu(_session);

        switch (selected.Value)
        {
            case 0:
                await AlbDownload.RunAsync().ConfigureAwait(false);
                return this;

            case 1:
                await AlbOptions.TopIpsForEndpointAsync(_session.Root, _session.SavedSelections).ConfigureAwait(false);
                return this;

            case 2:
                await AlbOptions.Top50IpsOverallAsync(_session.Root).ConfigureAwait(false);
                return this;

            case 3:
                await AlbOptions.Top50IpUriNoQueryAsync(_session.Root).ConfigureAwait(false);
                return this;

            case 4:
                await AlbOptions.AvgDurationByTargetNoQueryAsync(_session.Root).ConfigureAwait(false);
                return this;

            case 5:
                await AlbOptions.TrackRequestsPerIpPer5MinAsync(_session.Root).ConfigureAwait(false);
                return this;

            case 6:
                await AlbOptions.WafBlockedSummaryAsync(_session.Root).ConfigureAwait(false);
                return this;

            case 7:
                await AlbOptions.WafBlockedPerMinuteChartAsync(_session.Root).ConfigureAwait(false);
                return this;

            case 8:
                return new MainMenu(_session);

            default:
                return this;
        }
    }
}
