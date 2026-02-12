using LogHunter.Models;

namespace LogHunter.Services;

public sealed class SessionState
{
    public string Root { get; }
    public List<SavedSelection> SavedSelections { get; } = new();

    public SessionState(string root)
    {
        Root = root;
    }
}
