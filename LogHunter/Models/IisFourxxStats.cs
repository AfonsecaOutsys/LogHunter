namespace LogHunter.Models;

public sealed class IisFourxxStats
{
    public string Ip { get; }
    public long Total4xx { get; private set; }

    /// <summary>
    /// Per-status counts (e.g., 400,401,403,404,...).
    /// </summary>
    public Dictionary<int, long> StatusCounts { get; } = new();

    public IisFourxxStats(string ip) => Ip = ip;

    public void Add(int status)
    {
        Total4xx++;

        if (StatusCounts.TryGetValue(status, out var v))
            StatusCounts[status] = v + 1;
        else
            StatusCounts[status] = 1;
    }
}
