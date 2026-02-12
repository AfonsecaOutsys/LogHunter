namespace LogHunter.Services;

public static class AppFolders
{
    // Working directory (where user runs the EXE from)
    public static readonly string Base = Directory.GetCurrentDirectory();

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
