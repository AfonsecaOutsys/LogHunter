using Spectre.Console;

namespace LogHunter.Utils;

public static class ConsoleEx
{
    public static void Header(string title, string? subtitle = null)
    {
        AnsiConsole.Clear();

        var headerText = subtitle is null || string.IsNullOrWhiteSpace(subtitle)
            ? $"[bold]{Escape(title)}[/]"
            : $"[bold]{Escape(title)}[/]\n[grey]{Escape(subtitle)}[/]";

        var panel = new Panel(new Markup(headerText))
        {
            Border = BoxBorder.Rounded,
            Padding = new Padding(1, 0, 1, 0)
        };

        AnsiConsole.Write(panel);
        AnsiConsole.WriteLine();
    }

    public static string Prompt(string label)
    {
        // Keep behavior: returns trimmed string (may be empty)
        var v = AnsiConsole.Ask<string>(Escape(label));
        return (v ?? string.Empty).Trim();
    }

    public static int PromptIntInRange(string prompt, int min, int max)
    {
        var textPrompt = new TextPrompt<int>(Escape(prompt))
            .Validate(n =>
                n < min || n > max
                    ? ValidationResult.Error($"Enter a number between {min} and {max}.")
                    : ValidationResult.Success());

        return AnsiConsole.Prompt(textPrompt);
    }

    public static bool ReadYesNo(string prompt, bool defaultYes = true)
    {
        return AnsiConsole.Confirm(Escape(prompt), defaultYes);
    }

    public static void Pause(string msg = "Press ENTER to continue...")
    {
        AnsiConsole.MarkupLine($"[grey]{Escape(msg)}[/]");
        // keep the same "press enter" behavior (not any key)
        Console.ReadLine();
    }

    public static void DrawProgressBar(string label, double percent, int barWidth = 36)
    {
        // Keep the signature to avoid refactors.
        // Spectre’s Progress is better for long-running tasks, but this gives a simple, safe fallback.
        if (double.IsNaN(percent) || double.IsInfinity(percent)) percent = 0;
        if (percent < 0) percent = 0;
        if (percent > 100) percent = 100;

        int filled = (int)Math.Round((percent / 100.0) * barWidth);
        filled = Math.Clamp(filled, 0, barWidth);

        var bar = new string('█', filled) + new string('░', barWidth - filled);

        AnsiConsole.Markup($"\r{Escape(label)} [{bar}] {percent,6:0.0}%");

        if (percent >= 100.0)
            AnsiConsole.WriteLine();
    }

    private static string Escape(string s) => Markup.Escape(s ?? string.Empty);
}
