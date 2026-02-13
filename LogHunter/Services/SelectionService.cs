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
        table.AddColumn(new TableColumn("SavedAt (UTC)"));
        table.AddColumn(new TableColumn("Source"));
        table.AddColumn(new TableColumn("Rank").RightAligned());
        table.AddColumn(new TableColumn("Hits").RightAligned());
        table.AddColumn(new TableColumn("IP"));
        table.AddColumn(new TableColumn("Endpoint"));

        foreach (var s in saved.OrderByDescending(x => x.SavedAtUtc))
        {
            table.AddRow(
                s.SavedAtUtc.ToString("yyyy-MM-dd HH:mm:ss"),
                Markup.Escape(s.Source),
                s.Rank.ToString(),
                s.Hits.ToString("N0"),
                Markup.Escape(s.IP),
                Markup.Escape(s.Endpoint)
            );
        }

        AnsiConsole.Write(new Panel(table)
        {
            Header = new PanelHeader("Saved selections"),
            Border = BoxBorder.Rounded
        });
    }

    public static void ExportAll(string outputFolder, List<SavedSelection> saved)
    {
        Directory.CreateDirectory(outputFolder);

        var stamp = DateTime.Now.ToString("yyyyMMdd_HHmmss");
        var outFile = Path.Combine(outputFolder, $"SavedSelections_{stamp}.csv");

        using var w = new StreamWriter(outFile, false, Encoding.UTF8);
        w.WriteLine("SavedAtUtc,Source,Endpoint,Rank,IP,Hits");

        foreach (var s in saved.OrderBy(x => x.Source).ThenBy(x => x.Endpoint).ThenBy(x => x.Rank))
        {
            var endpoint = s.Endpoint.Replace("\"", "\"\"");
            w.WriteLine($"{s.SavedAtUtc:O},{s.Source},\"{endpoint}\",{s.Rank},{s.IP},{s.Hits}");
        }

        AnsiConsole.MarkupLine($"Exported: [green]{Markup.Escape(outFile)}[/]");
    }

    public static void ClearSavedSelections(List<SavedSelection> saved)
    {
        saved.Clear();
        AnsiConsole.MarkupLine("[green]Saved selections cleared.[/]");
    }
}
