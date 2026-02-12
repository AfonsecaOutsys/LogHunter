namespace LogHunter.Models;

public sealed record SavedSelection(
    DateTime SavedAtUtc,
    string Source,
    string Endpoint,
    int Rank,
    string IP,
    int Hits
);
