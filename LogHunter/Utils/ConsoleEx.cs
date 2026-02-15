using Spectre.Console;
using Spectre.Console.Rendering;
using System.Text;

namespace LogHunter.Utils;

public static class ConsoleEx
{
    // ---------- Header / Messages ----------

    public static void Header(string title, string? subtitle = null)
    {
        AnsiConsole.Clear();

        var headerText = string.IsNullOrWhiteSpace(subtitle)
            ? $"[bold]{Escape(title)}[/]"
            : $"[bold]{Escape(title)}[/]\n[grey]{Escape(subtitle!)}[/]";

        var panel = new Panel(new Markup(headerText))
        {
            Border = BoxBorder.Rounded,
            Padding = new Padding(1, 0, 1, 0)
        };

        AnsiConsole.Write(panel);
        AnsiConsole.WriteLine();
    }

    public static void Info(string msg) => AnsiConsole.MarkupLine($"[dim]{Escape(msg)}[/]");
    public static void Success(string msg) => AnsiConsole.MarkupLine($"[green]{Escape(msg)}[/]");
    public static void Warn(string msg) => AnsiConsole.MarkupLine($"[yellow]{Escape(msg)}[/]");
    public static void Error(string msg) => AnsiConsole.MarkupLine($"[red]{Escape(msg)}[/]");

    // ---------- Prompts ----------

    public static string Prompt(string label)
    {
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
        => AnsiConsole.Confirm(Escape(prompt), defaultYes);

    public static void Pause(string msg = "Press ENTER to continue...")
    {
        AnsiConsole.MarkupLine($"[grey]{Escape(msg)}[/]");
        Console.ReadLine();
    }

    // ---------- Cancellable line input (Esc cancels) ----------

    /// <summary>
    /// Reads a line from the console with basic editing. ESC cancels and returns null.
    /// ENTER accepts and returns the trimmed string (may be empty).
    /// </summary>
    public static string? ReadLineWithEsc(string label, bool trim = true)
    {
        AnsiConsole.Markup($"{Escape(label)} ");

        var sb = new StringBuilder();

        while (true)
        {
            var key = Console.ReadKey(intercept: true);

            if (key.Key == ConsoleKey.Escape)
            {
                AnsiConsole.WriteLine();
                return null;
            }

            if (key.Key == ConsoleKey.Enter)
            {
                AnsiConsole.WriteLine();
                var text = sb.ToString();
                return trim ? text.Trim() : text;
            }

            if (key.Key == ConsoleKey.Backspace)
            {
                if (sb.Length > 0)
                {
                    sb.Length--;
                    Console.Write("\b \b");
                }
                continue;
            }

            // Ctrl+U clears line
            if (key.Modifiers.HasFlag(ConsoleModifiers.Control) && key.Key == ConsoleKey.U)
            {
                while (sb.Length > 0)
                {
                    sb.Length--;
                    Console.Write("\b \b");
                }
                continue;
            }

            if (char.IsControl(key.KeyChar))
                continue;

            sb.Append(key.KeyChar);
            Console.Write(key.KeyChar);
        }
    }

    // ---------- Menu UI (manual keys + dynamic hint panel) ----------

    public sealed record MenuItem(string Label, string Hint);

    /// <summary>
    /// Renders a menu with a dynamic hint box + a keys box on the bottom.
    /// Keys: Up/Down move, 1-9 jump highlight (does NOT select), Enter selects, Esc returns null.
    /// Returns selected index or null if cancelled/back.
    /// </summary>
    public static int? Menu(string title, IReadOnlyList<MenuItem> items, int pageSize = 12)
    {
        if (items.Count == 0)
            return null;

        var selectedIndex = 0;
        int? result = null;

        var initial = BuildMenu(title, items, selectedIndex, pageSize);

        AnsiConsole.Live(initial)
            .AutoClear(true)
            .Start(ctx =>
            {
                // IMPORTANT: force first paint (fixes “blank until keypress”)
                ctx.UpdateTarget(BuildMenu(title, items, selectedIndex, pageSize));
                ctx.Refresh();

                while (true)
                {
                    var key = Console.ReadKey(intercept: true);

                    // Easter egg (Ctrl+Shift+Alt+F then G)
                    if (TryHandleEasterEgg(key))
                    {
                        // redraw menu after returning
                        ctx.UpdateTarget(BuildMenu(title, items, selectedIndex, pageSize));
                        ctx.Refresh();
                        continue;
                    }

                    if (key.Key == ConsoleKey.Escape)
                    {
                        result = null;
                        break;
                    }

                    if (key.Key == ConsoleKey.UpArrow)
                    {
                        selectedIndex = (selectedIndex - 1 + items.Count) % items.Count;
                        ctx.UpdateTarget(BuildMenu(title, items, selectedIndex, pageSize));
                        ctx.Refresh();
                        continue;
                    }

                    if (key.Key == ConsoleKey.DownArrow)
                    {
                        selectedIndex = (selectedIndex + 1) % items.Count;
                        ctx.UpdateTarget(BuildMenu(title, items, selectedIndex, pageSize));
                        ctx.Refresh();
                        continue;
                    }

                    if (key.Key == ConsoleKey.Enter)
                    {
                        result = selectedIndex;
                        break;
                    }

                    var digit = KeyToDigit(key);
                    if (digit is >= 1 and <= 9)
                    {
                        var idx = digit.Value - 1;
                        if (idx < items.Count)
                        {
                            selectedIndex = idx; // jump highlight only
                            ctx.UpdateTarget(BuildMenu(title, items, selectedIndex, pageSize));
                            ctx.Refresh();
                        }
                    }
                }
            });

        return result;
    }

    private static int? KeyToDigit(ConsoleKeyInfo key) =>
        key.Key switch
        {
            ConsoleKey.D1 or ConsoleKey.NumPad1 => 1,
            ConsoleKey.D2 or ConsoleKey.NumPad2 => 2,
            ConsoleKey.D3 or ConsoleKey.NumPad3 => 3,
            ConsoleKey.D4 or ConsoleKey.NumPad4 => 4,
            ConsoleKey.D5 or ConsoleKey.NumPad5 => 5,
            ConsoleKey.D6 or ConsoleKey.NumPad6 => 6,
            ConsoleKey.D7 or ConsoleKey.NumPad7 => 7,
            ConsoleKey.D8 or ConsoleKey.NumPad8 => 8,
            ConsoleKey.D9 or ConsoleKey.NumPad9 => 9,
            _ => null
        };

    private static IRenderable BuildMenu(string title, IReadOnlyList<MenuItem> items, int selectedIndex, int pageSize)
    {
        // Window over items
        var half = Math.Max(1, pageSize / 2);

        var start = Math.Max(0, selectedIndex - half);
        start = Math.Min(start, Math.Max(0, items.Count - pageSize));

        var end = Math.Min(items.Count, start + pageSize);

        // Left side: menu list
        var left = new Table()
            .NoBorder()
            .AddColumn(new TableColumn("").NoWrap())
            .AddColumn(new TableColumn("").NoWrap());

        for (var i = start; i < end; i++)
        {
            var isSel = i == selectedIndex;

            var prefix = isSel ? "[green]>[/] " : "  ";
            var idx = $"[grey]{i + 1}[/]";
            var label = isSel ? $"[bold]{Escape(items[i].Label)}[/]" : Escape(items[i].Label);

            left.AddRow($"{prefix}{idx}.", label);
        }

        // Right side: hint box (option A: fixed-ish width so it stays on the right)
        var hintText = items[selectedIndex].Hint ?? string.Empty;

        int termW = Math.Max(80, AnsiConsole.Profile.Width);
        int hintWidth = Math.Clamp(termW / 3, 38, 64);

        var hint = new Panel(new Markup(Escape(hintText)))
        {
            Header = new PanelHeader("[bold]Hint[/]"),
            Border = BoxBorder.Rounded,
            Width = hintWidth
        };

        var columns = new Columns(left, hint) { Expand = true };

        // Bottom: keys box
        var keysPanel = BuildKeysPanel();

        var rule = new Rule($"[bold]{Escape(title)}[/]");
        rule.RuleStyle("grey");

        return new Rows(rule, columns, new Padder(keysPanel).PadTop(1));
    }

    private static IRenderable BuildKeysPanel()
    {
        // Some terminals/fonts are weird with arrows; fall back if needed.
        var upDown = AnsiConsole.Profile.Capabilities.Unicode ? "↑/↓" : "Up/Down";

        var t = new Table()
            .NoBorder()
            .AddColumn(new TableColumn("").NoWrap())
            .AddColumn(new TableColumn("").NoWrap());

        t.AddRow("[grey]Enter[/]", "[grey]Select[/]");
        t.AddRow($"[grey]{Escape(upDown)}[/]", "[grey]Move[/]");
        t.AddRow("[grey]1-9[/]", "[grey]Jump highlight[/]");
        t.AddRow("[grey]Esc[/]", "[grey]Back[/]");

        return new Panel(t)
            .Header("[bold]Keys[/]")
            .Border(BoxBorder.Rounded)
            .Expand();
    }

    // ---------- Progress ----------

    public static void DrawProgressBar(string label, double percent, int barWidth = 36)
    {
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

    // ==========================================================
    // Easter egg (Ctrl+Shift+Alt+F then G)
    // ==========================================================

    private static DateTime _eggFPressedUtc = DateTime.MinValue;

    private static bool HasAllMods(ConsoleKeyInfo k) =>
        k.Modifiers.HasFlag(ConsoleModifiers.Control) &&
        k.Modifiers.HasFlag(ConsoleModifiers.Shift) &&
        k.Modifiers.HasFlag(ConsoleModifiers.Alt);

    /// <summary>
    /// Detects Ctrl+Shift+Alt+F then G (within ~900ms) and renders the clown.
    /// Returns true if the key was consumed.
    /// </summary>
    private static bool TryHandleEasterEgg(ConsoleKeyInfo key, int windowMs = 900)
    {
        if (!HasAllMods(key))
            return false;

        var now = DateTime.UtcNow;

        // Step 1: Ctrl+Shift+Alt+F
        if (key.Key == ConsoleKey.F)
        {
            _eggFPressedUtc = now;
            return true; // consume
        }

        // Step 2: Ctrl+Shift+Alt+G within window
        if (key.Key == ConsoleKey.G)
        {
            if ((now - _eggFPressedUtc).TotalMilliseconds <= windowMs)
            {
                _eggFPressedUtc = DateTime.MinValue;
                ShowClownEasterEgg();
                return true;
            }
        }

        return true; // has all mods but not our key? consume to avoid weirdness
    }

    private static void ShowClownEasterEgg()
    {
        const string clown = @"
     ,            _..._            ,
    {'.         .'     '.         .'}
   { ~ '.      _|=    __|_      .'  ~}
  { ~  ~ '-._ (___________) _.-'~  ~  }
 {~  ~  ~   ~.'           '. ~    ~    }
{  ~   ~  ~ /   /\     /\   \   ~    ~  }
{   ~   ~  /    __     __    \ ~   ~    }
 {   ~  /\/  -<( o)   ( o)>-  \/\ ~   ~}
  { ~   ;(      \/ .-. \/      );   ~ }
   { ~ ~\_  ()  ^ (   ) ^  ()  _/ ~  }
    '-._~ \   (`-._'-'_.-')   / ~_.-'
        '--\   `'._'""'_.'`   /--'
            \     \`-'/     /
             `\    '-'    /'
         jgs   `\       /'
                 '-...-'
";

        // Use raw Console to avoid any wrapping/reflow
        Console.CursorVisible = false;
        try
        {
            Console.Clear();

            int w = Math.Max(80, Console.WindowWidth);
            int h = Math.Max(24, Console.WindowHeight);

            static void WriteCentered(int row, string text)
            {
                if (row < 0 || row >= Console.WindowHeight) return;
                text ??= "";
                int x = Math.Max(0, (Console.WindowWidth - text.Length) / 2);
                Console.SetCursorPosition(x, row);
                Console.Write(text);
            }

            // Split lines safely (trim ONLY the first empty line from the verbatim string)
            var lines = clown.Replace("\r", "").Split('\n');
            if (lines.Length > 0 && lines[0].Length == 0)
                lines = lines.Skip(1).ToArray();

            int artHeight = lines.Length;
            int artWidth = lines.Max(l => l.Length);

            // Center art block
            int startY = Math.Max(1, (h - artHeight) / 2); // leave row 0 for FILIPE
            int startX = Math.Max(0, (w - artWidth) / 2);

            // Top title
            WriteCentered(0, "FILIPE");

            // Draw art
            for (int i = 0; i < lines.Length; i++)
            {
                int y = startY + i;
                if (y < 1 || y >= h - 1) continue;

                var line = lines[i];

                // If somehow wider than terminal, truncate (better than wrapping)
                if (line.Length > w)
                    line = line[..w];

                int x = Math.Clamp(startX, 0, Math.Max(0, w - line.Length));
                Console.SetCursorPosition(x, y);
                Console.Write(line);
            }

            // Bottom footer
            WriteCentered(h - 1, "BOOMER");

            // Wait
            Console.SetCursorPosition(0, h - 1);
            Console.ReadLine();
        }
        finally
        {
            Console.CursorVisible = true;
        }
    }

}
