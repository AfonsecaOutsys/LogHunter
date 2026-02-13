using Spectre.Console;

namespace LogHunter.Utils;

public static class SpectreDateTimePicker
{
    private enum Field { Year, Month, Day, Hour, Minute }

    public static DateTime PickUtc(
        string label,
        DateTime initialUtc,
        DateTime? minUtc = null,
        DateTime? maxUtc = null)
    {
        var dt = EnsureUtc(initialUtc);
        dt = SnapTo5Min(dt);

        if (minUtc.HasValue) minUtc = EnsureUtc(minUtc.Value);
        if (maxUtc.HasValue) maxUtc = EnsureUtc(maxUtc.Value);

        dt = Clamp(dt, minUtc, maxUtc);

        var field = Field.Day;

        while (true)
        {
            AnsiConsole.Clear();

            var help =
                "[grey]←/→ field   ↑/↓ change   Enter confirm   Esc cancel[/]\n" +
                "[grey]Minute changes in 5-min steps (UTC)[/]";
            AnsiConsole.Write(new Panel(help)
            {
                Header = new PanelHeader(label),
                Border = BoxBorder.Rounded
            });

            AnsiConsole.WriteLine();
            AnsiConsole.MarkupLine(Render(dt, field));

            var key = Console.ReadKey(intercept: true);

            if (key.Key == ConsoleKey.Enter)
                return dt;

            if (key.Key == ConsoleKey.Escape)
                throw new OperationCanceledException("User cancelled date/time selection.");

            switch (key.Key)
            {
                case ConsoleKey.LeftArrow:
                    field = Prev(field);
                    break;
                case ConsoleKey.RightArrow:
                    field = Next(field);
                    break;
                case ConsoleKey.UpArrow:
                    dt = Adjust(dt, field, +1);
                    break;
                case ConsoleKey.DownArrow:
                    dt = Adjust(dt, field, -1);
                    break;
            }

            dt = SnapTo5Min(dt);
            dt = Clamp(dt, minUtc, maxUtc);
        }
    }

    private static string Render(DateTime dtUtc, Field field)
    {
        string Y(string s, Field f) => field == f ? $"[black on yellow] {s} [/]" : $"[grey] {s} [/]";
        var y = Y(dtUtc.Year.ToString("D4"), Field.Year);
        var m = Y(dtUtc.Month.ToString("D2"), Field.Month);
        var d = Y(dtUtc.Day.ToString("D2"), Field.Day);
        var h = Y(dtUtc.Hour.ToString("D2"), Field.Hour);
        var mm = Y(dtUtc.Minute.ToString("D2"), Field.Minute);

        return $"[bold]Selected:[/] {y}-" + $"{m}-" + $"{d}  {h}:{mm}  [grey]UTC[/]";
    }

    private static DateTime Adjust(DateTime dtUtc, Field field, int delta) =>
        field switch
        {
            Field.Year => dtUtc.AddYears(delta),
            Field.Month => dtUtc.AddMonths(delta),
            Field.Day => dtUtc.AddDays(delta),
            Field.Hour => dtUtc.AddHours(delta),
            Field.Minute => dtUtc.AddMinutes(delta * 5),
            _ => dtUtc
        };

    private static DateTime SnapTo5Min(DateTime dtUtc)
    {
        var snapped = (dtUtc.Minute / 5) * 5;
        return new DateTime(dtUtc.Year, dtUtc.Month, dtUtc.Day, dtUtc.Hour, snapped, 0, DateTimeKind.Utc);
    }

    private static DateTime Clamp(DateTime dtUtc, DateTime? minUtc, DateTime? maxUtc)
    {
        if (minUtc.HasValue && dtUtc < minUtc.Value) return minUtc.Value;
        if (maxUtc.HasValue && dtUtc > maxUtc.Value) return maxUtc.Value;
        return dtUtc;
    }

    private static DateTime EnsureUtc(DateTime dt) =>
        dt.Kind == DateTimeKind.Utc ? dt : DateTime.SpecifyKind(dt.ToUniversalTime(), DateTimeKind.Utc);

    private static Field Prev(Field f) => f == Field.Year ? Field.Minute : (Field)((int)f - 1);
    private static Field Next(Field f) => f == Field.Minute ? Field.Year : (Field)((int)f + 1);
}
