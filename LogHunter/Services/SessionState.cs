using LogHunter.Models;
using System;
using System.Collections.Generic;

namespace LogHunter.Services;

public sealed class SessionState
{
    public string Root { get; }

    public List<SavedSelection> SavedSelections { get; } = new();

    // IIS burst tracking (shared across IIS options during a run)
    public HashSet<string> IisBurstIps { get; } = new(StringComparer.OrdinalIgnoreCase);
    public DateTime? IisBurstIpsUpdatedUtc { get; private set; }

    // Platform scanners (cached results during a run)
    public Dictionary<string, int>? PlatformSuspiciousIpHits { get; set; }
    public DateTime? PlatformSuspiciousIpHitsUpdatedUtc { get; set; }
    public Dictionary<string, int>? PlatformAuthedIpHits { get; set; }
    public DateTime? PlatformAuthedIpHitsUpdatedUtc { get; set; }

    public SessionState(string root)
    {
        Root = root;
    }

    public void ReplaceIisBurstIps(IEnumerable<string> ips)
    {
        IisBurstIps.Clear();

        foreach (var ip in ips)
        {
            if (string.IsNullOrWhiteSpace(ip))
                continue;

            IisBurstIps.Add(ip.Trim());
        }

        IisBurstIpsUpdatedUtc = DateTime.UtcNow;
    }
}