using LogHunter.Models;

namespace LogHunter.Services;

public sealed class SessionState
{
    public string Root { get; }
    public List<SavedSelection> SavedSelections { get; } = new();

    public SessionState(string root)
    {
        Root = root;
    }

public HashSet<string> IisBurstIps { get; } = new(StringComparer.OrdinalIgnoreCase);
    public DateTime? IisBurstIpsUpdatedUtc { get; private set; }

    public void ReplaceIisBurstIps(IEnumerable<string> ips)
    {
        IisBurstIps.Clear();

        foreach (var ip in ips)
        {
            if (!string.IsNullOrWhiteSpace(ip))
                IisBurstIps.Add(ip.Trim());
        }

        IisBurstIpsUpdatedUtc = DateTime.UtcNow;
    }
    public Dictionary<string, int>? PlatformSuspiciousIpHits { get; set; }
    public DateTime? PlatformSuspiciousIpHitsUpdatedUtc { get; set; }
    public Dictionary<string, int>? PlatformAuthedIpHits { get; set; }
    public DateTime? PlatformAuthedIpHitsUpdatedUtc { get; set; }
}