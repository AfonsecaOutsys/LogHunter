// Menus/PlatformMenu.cs
using LogHunter.Services;
using LogHunter.Utils;
using System.Threading;
using System.Threading.Tasks;

namespace LogHunter.Menus;

public sealed class PlatformMenu : IMenu
{
    private readonly SessionState _session;

    public PlatformMenu(SessionState session) => _session = session;

    public async Task<IMenu?> ShowAsync(CancellationToken ct = default)
    {
        ConsoleEx.Header("Platform", $"Workspace: {_session.Root}");

        var suspiciousCount = _session.PlatformSuspiciousIpHits?.Count ?? 0;
        var authedCount = _session.PlatformAuthedIpHits?.Count ?? 0;

        var items = new[]
        {
            new ConsoleEx.MenuItem(
                "Suspicious requests: extract IPs",
                "Scan Platform log exports (CSV/XLSX) for common suspicious patterns.\n" +
                "Extract X-Forwarded-For (preferred), otherwise ClientIp.\n" +
                "Stores results in session selections and updates the suspicious-IP cache."),

            new ConsoleEx.MenuItem(
                $"Suspicious IPs: authenticated activity check ({suspiciousCount} IPs)",
                "Use the suspicious-IP cache from the previous step.\n" +
                "Scan other Platform log exports and count rows where UserId != 0.\n" +
                "Stores an authenticated-IP cache for later use."),

            new ConsoleEx.MenuItem(
                $"Authenticated IP cache ({authedCount})",
                "Info-only view.\nRun the authenticated activity check to populate/update this cache."),

            new ConsoleEx.MenuItem(
                "Back",
                "Return to the main menu.")
        };

        var selected = ConsoleEx.Menu("Platform menu", items, pageSize: 10);

        // Esc = back
        if (selected is null)
            return new MainMenu(_session);

        switch (selected.Value)
        {
            case 0:
                await PlatformOptions.SuspiciousRequestsExtractIpsAsync(_session, ct).ConfigureAwait(false);
                return this;

            case 1:
                await PlatformOptions.CheckSuspiciousIpsAuthenticatedAsync(_session, ct).ConfigureAwait(false);
                return this;

            case 2:
                ConsoleEx.Header("Platform: authenticated IP cache", $"IPs: {authedCount}");
                ConsoleEx.Info("Run 'Suspicious IPs: authenticated activity check' to populate/update the cache.");
                ConsoleEx.Pause("Press Enter to return...");
                return this;

            case 3:
                return new MainMenu(_session);

            default:
                return this;
        }
    }
}