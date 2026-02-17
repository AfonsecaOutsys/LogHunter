using LogHunter.Utils;
using Spectre.Console;

namespace LogHunter.Services;

public static class IisOption_TopEndpointsByLatency
{
    public static Task RunAsync(string root, CancellationToken ct = default)
    {
        ConsoleEx.Header("IIS: Top endpoints by latency (placeholder)");
        AnsiConsole.MarkupLine("[grey]Not implemented yet.[/]");
        AnsiConsole.MarkupLine($"[dim]Expected input folder:[/] {Markup.Escape(Path.Combine(root, "IIS"))}");
        ConsoleEx.Pause();
        return Task.CompletedTask;
    }
}
