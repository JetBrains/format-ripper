using System;
using System.Collections.Generic;
using System.Linq;
using NUnit.Framework;

namespace JetBrains.FormatRipper.Tests
{
  internal static class SymbolUtil
  {
    private const int MaxEdgeCount = 100;
    private const int MaxLookupErrorCount = 20;

    // Note: the unstripped binaries have too many local and debugging symbols to look up all of them
    private const int MaxNonGlobalLookupCount = 1000;

    // Note: every linear lookup scans the whole symbol table, so checking all the names is quadratic
    public const int MaxLinearLookupSymbolCount = 2000;

    // Note: '!' and '~' are the lowest and the highest printable ASCII characters, so the names sorted by bytes are between
    // them, they check the edges of the binary search
    private static readonly string[] ourArtificialNames = { "!", "~" };

    public static T[] SelectEdges<T>(IList<T> symbols) => symbols.Count <= 2 * MaxEdgeCount
      ? symbols.ToArray()
      : symbols.Take(MaxEdgeCount).Concat(symbols.Skip(symbols.Count - MaxEdgeCount)).ToArray();

    /// <summary>
    /// Makes the lookups for every named global symbol with a missing name next to each of them, for the names of the
    /// non-global symbols only, for the empty and the artificial names. The expected index is the one of the first global
    /// definition, otherwise of the first global undefined reference.
    /// </summary>
    public static List<Lookup> MakeLookups<T>(IList<T> symbols, Func<T, string?> getName, Func<T, bool> isGlobal, Func<T, bool> isDefined)
    {
      if (symbols.Count == 0)
        return new List<Lookup>();

      var allNames = new HashSet<string>();
      foreach (var symbol in symbols)
        if (getName(symbol) is { } name)
          allNames.Add(name);

      var globalLookups = GetGlobalLookups(symbols, getName, isGlobal, isDefined);
      var globalNames = new HashSet<string>(globalLookups.Select(x => x.Name));

      var lookups = new List<Lookup>();
      foreach (var lookup in globalLookups)
      {
        var name = lookup.Name;
        lookups.Add(lookup);
        lookups.Add(new Lookup(MakeMissing(allNames, name.Length > 1 ? name.Substring(0, name.Length - 1) : name + "~"), null));
      }

      lookups.AddRange(symbols
        .Where(x => !isGlobal(x))
        .Select(getName)
        .Where(x => x is { Length: > 0 } && !globalNames.Contains(x))
        .Distinct()
        .Take(MaxNonGlobalLookupCount)
        .Select(x => new Lookup(x!, null)));

      // Note: the empty name is never found even when there are the symbols without names
      lookups.Add(new Lookup("", null));
      foreach (var name in ourArtificialNames)
        lookups.Add(new Lookup(MakeMissing(allNames, name), null));
      return lookups;
    }

    public static void AssertLookups(ICollection<string> errors)
    {
      if (errors.Count > 0)
        Assert.Fail($"{errors.Count} lookup errors:{Environment.NewLine}{string.Join(Environment.NewLine, errors.Take(MaxLookupErrorCount).ToArray())}");
    }

    private static List<Lookup> GetGlobalLookups<T>(IList<T> symbols, Func<T, string?> getName, Func<T, bool> isGlobal, Func<T, bool> isDefined)
    {
      var names = new List<string>();
      var definitions = new Dictionary<string, int>();
      var references = new Dictionary<string, int>();
      for (var n = 0; n < symbols.Count; ++n)
      {
        var symbol = symbols[n];
        if (getName(symbol) is not { Length: > 0 } name || !isGlobal(symbol))
          continue;
        if (!definitions.ContainsKey(name) && !references.ContainsKey(name))
          names.Add(name);
        var indexes = isDefined(symbol) ? definitions : references;
        if (!indexes.ContainsKey(name))
          indexes.Add(name, n);
      }

      return names.Select(x => new Lookup(x, definitions.TryGetValue(x, out var index) ? index : references[x])).ToList();
    }

    private static string MakeMissing(HashSet<string> names, string name)
    {
      while (names.Contains(name))
        name += "~";
      return name;
    }
  }
}
