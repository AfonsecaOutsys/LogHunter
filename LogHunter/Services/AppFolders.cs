using System;
using System.IO;

namespace LogHunter.Services;

public static class AppFolders
{
    // Creates/reads folders next to the running EXE (stable for Debug/Release/publish/single-file).
    public static readonly string Base = Path.GetFullPath(AppContext.BaseDirectory);

    public static readonly string ALB = Path.Combine(Base, "ALB");
    public static readonly string IIS = Path.Combine(Base, "IIS");
    public static readonly string PlatformLogs = Path.Combine(Base, "PlatformLogs");
    public static readonly string Output = Path.Combine(Base, "output");

    public static void Ensure()
    {
        Directory.CreateDirectory(ALB);
        Directory.CreateDirectory(IIS);
        Directory.CreateDirectory(PlatformLogs);
        Directory.CreateDirectory(Output);
    }
}