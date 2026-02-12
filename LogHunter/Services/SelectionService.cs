using System.Text;
using LogHunter.Models;

namespace LogHunter.Services;

public static class SelectionService
{
    public static void ShowSavedSelections(List<SavedSelection> saved)
    {
        if (saved.Count == 0)
        {
            Console.WriteLine("(no saved selections)");
            return;
        }

        Console.WriteLine($"{"SavedAt(UTC)",20}  {"Source",6}  {"Rank",4}  {"Hits",10}  {"IP",-15}  Endpoint");
        Console.WriteLine(new string('-', 110));

        foreach (var s in saved.OrderByDescending(x => x.SavedAtUtc))
        {
            Console.WriteLine($"{s.SavedAtUtc:yyyy-MM-dd HH:mm:ss}  {s.Source,6}  {s.Rank,4}  {s.Hits,10}  {s.IP,-15}  {s.Endpoint}");
        }
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

        Console.WriteLine($"Exported: {outFile}");
    }

    public static void ClearSavedSelections(List<SavedSelection> saved)
    {
        saved.Clear();
        Console.WriteLine("Saved selections cleared.");
    }
}
