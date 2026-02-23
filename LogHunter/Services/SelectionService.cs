// Services/SelectionService.cs
using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text;
using LogHunter.Models;
using Spectre.Console;

namespace LogHunter.Services;

public static class SelectionService
{
    public static void ShowSavedSelections(List<SavedSelection> saved)
    {
        if (saved.Count == 0)
        {
            AnsiConsole.MarkupLine("[grey](no saved selections)[/]");
            return;
        }

        var table = new Table().RoundedBorder();
        table.AddColumn(new TableColumn("SavedAt (UTC)").NoWrap());
        table.AddColumn(new TableColumn("Source").NoWrap());
        table.AddColumn(new TableColumn("Rank").RightAligned().NoWrap());
        table.AddColumn(new TableColumn("Hits").RightAligned().NoWrap());
        table.AddColumn(new TableColumn("IP").NoWrap());
        table.AddColumn(new TableColumn("Endpoint"));

        foreach (var s in saved.OrderByDescending(x => x.SavedAtUtc))
        {
            table.AddRow(
                s.SavedAtUtc.ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture) + "Z",
                Markup.Escape(s.Source),
                s.Rank.ToString(CultureInfo.InvariantCulture),
                s.Hits.ToString("N0", CultureInfo.InvariantCulture),
                Markup.Escape(s.IP),
                Markup.Escape(s.Endpoint)
            );
        }

        AnsiConsole.Write(new Panel(table)
        {
            Header = new PanelHeader($"Saved selections ({saved.Count})"),
            Border = BoxBorder.Rounded
        });

        AnsiConsole.WriteLine();
        AnsiConsole.MarkupLine("[dim]Tip:[/] Use [bold]Export[/] from the main menu to write these to CSV.");
    }

    public static void ExportAll(string outputFolder, List<SavedSelection> saved)
    {
        if (saved.Count == 0)
        {
            AnsiConsole.MarkupLine("[grey](no saved selections to export)[/]");
            return;
        }

        Directory.CreateDirectory(outputFolder);

        var stamp = DateTime.UtcNow.ToString("yyyyMMdd_HHmmss", CultureInfo.InvariantCulture);
        var outFile = Path.Combine(outputFolder, $"SavedSelections_{stamp}.csv");

        using var w = new StreamWriter(outFile, false, new UTF8Encoding(encoderShouldEmitUTF8Identifier: false));
        w.WriteLine("SavedAtUtc,Source,Endpoint,Rank,IP,Hits");

        foreach (var s in saved
                     .OrderBy(x => x.Source, StringComparer.OrdinalIgnoreCase)
                     .ThenBy(x => x.Endpoint, StringComparer.OrdinalIgnoreCase)
                     .ThenBy(x => x.Rank))
        {
            w.WriteLine(string.Join(",",
                Csv(s.SavedAtUtc.ToString("O", CultureInfo.InvariantCulture)),
                Csv(s.Source),
                Csv(s.Endpoint),
                s.Rank.ToString(CultureInfo.InvariantCulture),
                Csv(s.IP),
                s.Hits.ToString(CultureInfo.InvariantCulture)
            ));
        }

        AnsiConsole.MarkupLine($"Exported: [green]{Markup.Escape(outFile)}[/]");
        AnsiConsole.MarkupLine($"[dim]Rows:[/] {saved.Count.ToString("N0", CultureInfo.InvariantCulture)}");
    }

    public static void ClearSavedSelections(List<SavedSelection> saved)
    {
        saved.Clear();
        AnsiConsole.MarkupLine("[green]Saved selections cleared.[/]");
    }

    private static string Csv(string? s)
    {
        if (string.IsNullOrEmpty(s))
            return "";

        var needsQuotes = s.IndexOfAny(new[] { ',', '"', '\n', '\r' }) >= 0;
        if (!needsQuotes) return s;

        return "\"" + s.Replace("\"", "\"\"") + "\"";
    }
}