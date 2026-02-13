using LogHunter.Services;
using LogHunter.Utils;
using Spectre.Console;

namespace LogHunter.Menus;

public sealed class AlbMenu : IMenu
{
    private readonly SessionState _session;

    public AlbMenu(SessionState session) => _session = session;

    public async Task<IMenu?> ShowAsync()
    {
        ConsoleEx.Header("ALB Menu", $"Workspace: {_session.Root}");

        var choice = AnsiConsole.Prompt(
            new SelectionPrompt<string>()
                .Title("Select an option:")
                .PageSize(12)
                .AddChoices(new[]
                {
                    "1 - Download ALB logs",
                    "2 - Top IPs for endpoint/path fragment",
                    "3 - Top 50 IPs overall",
                    "4 - Top 50 IPs by URI (no query)",
                    "5 - Requests (no query) ordered by AVG duration filtered by target",
                    "6 - Track requests per IP per 5 minutes (chart)",
                    "7 - WAF blocked summary + Top 50 blocked requests",
                    "0 - Back"
                })
        );

        switch (choice[0])
        {
            case '1':
                await AlbDownload.RunAsync().ConfigureAwait(false);
                return this;

            case '2':
                await AlbOptions.TopIpsForEndpointAsync(_session.Root, _session.SavedSelections).ConfigureAwait(false);
                return this;

            case '3':
                await AlbOptions.Top50IpsOverallAsync(_session.Root).ConfigureAwait(false);
                return this;

            case '4':
                await AlbOptions.Top50IpUriNoQueryAsync(_session.Root).ConfigureAwait(false);
                return this;

            case '5':
                await AlbOptions.AvgDurationByTargetNoQueryAsync(_session.Root).ConfigureAwait(false);
                return this;

            case '6':
                await AlbOptions.TrackRequestsPerIpPer5MinAsync(_session.Root).ConfigureAwait(false);
                return this;

            case '7':
                await AlbOptions.WafBlockedSummaryAsync(_session.Root).ConfigureAwait(false);
                return this;

            case '0':
                return new MainMenu(_session);

            default:
                return this;
        }
    }
}
