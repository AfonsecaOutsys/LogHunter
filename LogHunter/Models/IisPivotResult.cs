namespace LogHunter.Models;

public sealed class IisPivotResult
{
    public string Ip { get; }
    public string? OutputFilePath { get; set; }

    public long Total2xx { get; private set; }
    public long Total3xx { get; private set; }

    /// <summary>
    /// Per-status counts for 2xx/3xx (e.g., 200,302,304,...).
    /// </summary>
    public Dictionary<int, long> StatusCounts { get; } = new();

    /// <summary>
    /// URI stem counts for 2xx/3xx (grouped by cs-uri-stem).
    /// </summary>
    private readonly Dictionary<string, long> _uriCounts = new(StringComparer.OrdinalIgnoreCase);

    public IisPivotResult(string ip) => Ip = ip;

    public void Add(int status)
    {
        if (status is >= 200 and <= 299) Total2xx++;
        else if (status is >= 300 and <= 399) Total3xx++;

        if (StatusCounts.TryGetValue(status, out var v))
            StatusCounts[status] = v + 1;
        else
            StatusCounts[status] = 1;
    }

    public void AddUri(string uriStem)
    {
        if (_uriCounts.TryGetValue(uriStem, out var v))
            _uriCounts[uriStem] = v + 1;
        else
            _uriCounts[uriStem] = 1;
    }

    public List<(string UriStem, long Count)> TopUris(int take)
        => _uriCounts
            .OrderByDescending(kv => kv.Value)
            .ThenBy(kv => kv.Key, StringComparer.OrdinalIgnoreCase)
            .Take(take)
            .Select(kv => (kv.Key, kv.Value))
            .ToList();
}
