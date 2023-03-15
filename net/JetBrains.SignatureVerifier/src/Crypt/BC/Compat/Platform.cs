using System.Collections;

namespace JetBrains.SignatureVerifier.Crypt.BC.Compat
{
  internal static class Platform
  {
    internal static IList CreateArrayList() => new ArrayList();

    internal static IList CreateArrayList(int capacity) => new ArrayList(capacity);

    internal static IList CreateArrayList(ICollection collection) => new ArrayList(collection);

    internal static IList CreateArrayList(IEnumerable collection)
    {
      var result = new ArrayList();
      foreach (var o in collection) result.Add(o);

      return result;
    }

    internal static IDictionary CreateHashtable() => new Hashtable();
  }
}