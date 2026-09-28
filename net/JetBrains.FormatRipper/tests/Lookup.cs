namespace JetBrains.FormatRipper.Tests
{
  internal sealed class Lookup
  {
    public readonly string Name;
    public readonly int? Index;

    internal Lookup(string name, int? index)
    {
      Name = name;
      Index = index;
    }
  }
}
