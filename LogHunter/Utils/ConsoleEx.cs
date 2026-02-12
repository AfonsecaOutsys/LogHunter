namespace LogHunter.Utils;

public static class ConsoleEx
{
    public static void Header(string title, string? subtitle = null)
    {
        Console.Clear();
        Console.WriteLine("===============================");
        Console.WriteLine($" {title}");
        Console.WriteLine("===============================");
        if (!string.IsNullOrWhiteSpace(subtitle))
            Console.WriteLine(subtitle);
        Console.WriteLine();
    }

    public static string Prompt(string label)
    {
        Console.Write(label);
        return (Console.ReadLine() ?? "").Trim();
    }

    public static int PromptIntInRange(string prompt, int min, int max)
    {
        while (true)
        {
            var raw = Prompt(prompt);
            if (int.TryParse(raw, out var n) && n >= min && n <= max)
                return n;

            Console.WriteLine($"Enter a number between {min} and {max}.");
        }
    }

    public static bool ReadYesNo(string prompt, bool defaultYes = true)
    {
        var suffix = defaultYes ? "[Y/n]" : "[y/N]";
        while (true)
        {
            var v = Prompt($"{prompt} {suffix} ").ToLowerInvariant();
            if (string.IsNullOrWhiteSpace(v)) return defaultYes;
            if (v is "y" or "yes") return true;
            if (v is "n" or "no") return false;
            Console.WriteLine("Please answer Y or N.");
        }
    }

    public static void Pause(string msg = "Press ENTER to continue...")
    {
        Console.WriteLine();
        Console.Write(msg);
        Console.ReadLine();
    }

    public static void DrawProgressBar(string label, double percent, int barWidth = 36)
    {
        if (double.IsNaN(percent) || double.IsInfinity(percent)) percent = 0;
        if (percent < 0) percent = 0;
        if (percent > 100) percent = 100;

        int filled = (int)Math.Round((percent / 100.0) * barWidth);
        if (filled < 0) filled = 0;
        if (filled > barWidth) filled = barWidth;

        var bar = new string('█', filled) + new string('░', barWidth - filled);

        Console.Write($"\r{label} [{bar}] {percent,6:0.0}%");

        if (percent >= 100.0)
            Console.WriteLine();
    }
}
