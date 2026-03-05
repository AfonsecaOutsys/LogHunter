using System;
using System.IO;
using System.Linq;
using System.Reflection;

namespace LogHunter.Services;

public static class EmbeddedAssets
{
    public static void EnsureTabulatorAssets(string root, bool overwrite = false)
    {
        if (string.IsNullOrWhiteSpace(root))
            throw new ArgumentException("Root path is required.", nameof(root));

        var assetsDir = Path.Combine(root, "ALB", "configs", "_assets");
        Directory.CreateDirectory(assetsDir);

        var jsOut = Path.Combine(assetsDir, "tabulator.min.js");
        var cssOut = Path.Combine(assetsDir, "tabulator.min.css");

        if (overwrite || !File.Exists(jsOut))
            ExtractBySuffix(".tabulator.min.js", jsOut);

        if (overwrite || !File.Exists(cssOut))
            ExtractBySuffix(".tabulator.min.css", cssOut);
    }

    private static void ExtractBySuffix(string suffix, string outputPath)
    {
        var asm = Assembly.GetExecutingAssembly();

        var resName = asm.GetManifestResourceNames()
            .FirstOrDefault(n => n.EndsWith(suffix, StringComparison.OrdinalIgnoreCase));

        if (resName is null)
            throw new FileNotFoundException($"Embedded resource not found (suffix match): {suffix}");

        using var stream = asm.GetManifestResourceStream(resName);
        if (stream is null)
            throw new FileNotFoundException($"Embedded resource stream not found: {resName}");

        Directory.CreateDirectory(Path.GetDirectoryName(outputPath)!);

        using var fs = File.Create(outputPath);
        stream.CopyTo(fs);
    }
}
