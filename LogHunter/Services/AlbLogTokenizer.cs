using System.Text;

namespace LogHunter.Services;

public static class AlbLogTokenizer
{
    /// <summary>
    /// Splits an ALB log line into tokens, treating quoted segments as single tokens.
    /// Quotes are removed from returned tokens.
    /// </summary>
    public static List<string> Tokenize(string line)
    {
        var tokens = new List<string>(48);
        if (string.IsNullOrWhiteSpace(line)) return tokens;

        var sb = new StringBuilder(line.Length);
        bool inQuotes = false;

        for (int i = 0; i < line.Length; i++)
        {
            char c = line[i];

            if (c == '"')
            {
                inQuotes = !inQuotes;
                continue; // drop quotes
            }

            if (!inQuotes && c == ' ')
            {
                if (sb.Length > 0)
                {
                    tokens.Add(sb.ToString());
                    sb.Clear();
                }
                continue;
            }

            sb.Append(c);
        }

        if (sb.Length > 0)
            tokens.Add(sb.ToString());

        return tokens;
    }
}
