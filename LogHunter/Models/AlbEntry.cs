namespace LogHunter.Models;

public readonly record struct AlbEntry(
    DateTime TimestampUtc,
    string ClientIp,
    string UriNoQuery,
    string TargetHostPort,
    double TargetProcessingTimeSeconds,
    string ActionsExecuted
);
