using System.Threading;
using System.Threading.Tasks;

namespace LogHunter.Menus;

public interface IMenu
{
    Task<IMenu?> ShowAsync(CancellationToken ct = default);
}