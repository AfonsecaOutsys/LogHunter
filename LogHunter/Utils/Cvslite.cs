// Utils/CsvLite.cs
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace LogHunter.Utils;

public static class CsvLite
{
    public static char DetectDelimiter(string headerLine)
    {
        if (headerLine is null) throw new ArgumentNullException(nameof(headerLine));

        var comma = headerLine.Count(c => c == ',');
        var semi = headerLine.Count(c => c == ';');
        var tab = headerLine.Count(c => c == '\t');

        if (tab > comma && tab > semi) return '\t';
        if (semi > comma) return ';';
        return ',';
    }

    public static List<string> Split(string line, char delimiter)
    {
        var result = new List<string>();
        if (line is null) return result;

        if (line.Length == 0)
        {
            result.Add("");
            return result;
        }

        // Pre-size to reduce reallocs (rough estimate)
        result.Capacity = Math.Max(4, 1 + line.Count(c => c == delimiter));

        var cur = new StringBuilder(line.Length);
        var inQuotes = false;

        for (var i = 0; i < line.Length; i++)
        {
            var ch = line[i];

            if (inQuotes)
            {
                if (ch == '"')
                {
                    // Escaped quote ("")
                    if (i + 1 < line.Length && line[i + 1] == '"')
                    {
                        cur.Append('"');
                        i++;
                        continue;
                    }

                    inQuotes = false;
                    continue;
                }

                cur.Append(ch);
                continue;
            }

            if (ch == '"')
            {
                inQuotes = true;
                continue;
            }

            if (ch == delimiter)
            {
                result.Add(cur.ToString());
                cur.Clear();
                continue;
            }

            cur.Append(ch);
        }

        result.Add(cur.ToString());
        return result;
    }
}