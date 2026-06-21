using System.Collections.Generic;
using System.Linq;

namespace JetBrains.FormatRipper.Tests
{
  internal static class SymbolUtil
  {
    private const int MaxEdgeCount = 100;

    public static T[] SelectEdges<T>(IList<T> symbols) => symbols.Count <= 2 * MaxEdgeCount
      ? symbols.ToArray()
      : symbols.Take(MaxEdgeCount).Concat(symbols.Skip(symbols.Count - MaxEdgeCount)).ToArray();
  }
}
