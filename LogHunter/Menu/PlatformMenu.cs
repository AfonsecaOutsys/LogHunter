// Menus/PlatformMenu.cs
using LogHunter.Services;
using LogHunter.Utils;

namespace LogHunter.Menus;

public sealed class PlatformMenu : IMenu
{
    private readonly SessionState _session;

    public PlatformMenu(SessionState session) => _session = session;

    public async Task<IMenu?> ShowAsync(CancellationToken ct = default)
    {
        ConsoleEx.Header("Platform logs", $"Workspace: {_session.Root}");

        var suspiciousCount = _session.PlatformSuspiciousIpHits?.Count ?? 0;
        var authedCount = _session.PlatformAuthedIpHits?.Count ?? 0;

        var items = new[]
        {
            new ConsoleEx.MenuItem(
                "Suspicious requests > extract IPs",
                "Scan /platformlogs (CSV + XLSX) for:\n" +
                "- A potentially dangerous Request.Path...\n" +
                "- The file * does not exist.\n\n" +
                "Extract X-Forwarded-For (preferred) else ClientIp.\n" +
                "Save results into session selections + Platform suspicious cache."
            ),
            new ConsoleEx.MenuItem(
                $"Suspicious IPs > authenticated activity check ({suspiciousCount} IPs)",
                "Uses the suspicious IP set from the previous step and scans other Platform log exports.\n" +
                "Counts rows where UserId != 0 (past login).\n" +
                "Outputs per-log-type hit counts and saves an 'authenticated IPs' cache for later."
            ),
            new ConsoleEx.MenuItem(
                $"(Info) Authenticated IP cache currently has ({authedCount})",
                "This is populated by the authenticated activity check. It can be used later for AbuseIP / reporting."
            ),
            new ConsoleEx.MenuItem("Back", "Return to main menu.")
        };

        var selected = ConsoleEx.Menu("Select an option:", items, pageSize: 10);

        if (selected is null)
            return new MainMenu(_session);

        switch (selected.Value)
        {
            case 0:
                await PlatformOptions.SuspiciousRequestsExtractIpsAsync(_session, ct);
                return this;

            case 1:
                await PlatformOptions.CheckSuspiciousIpsAuthenticatedAsync(_session, ct);
                return this;

            case 2:
                ConsoleEx.Header("Platform • Authenticated IP cache", $"IPs: {authedCount}");
                ConsoleEx.Info("Run 'Suspicious IPs → authenticated activity check' to populate/update it.");
                ConsoleEx.Pause();
                return this;

            case 3:
                return new MainMenu(_session);

            default:
                return this;
        }
    }
}