namespace DecryptToe.Models;
public sealed record ModuleItem(string Name, string Path, long BaseAddress, int Size)
{
    public string Address => $"0x{BaseAddress:X16}";
    public string Display => $"{Name}  |  0x{BaseAddress:X16}  |  {Size / 1024.0 / 1024:0.0} MB";
}
