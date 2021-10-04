using System.Collections;
using System.Collections.Generic;

namespace JetBrains.SignatureVerifier.BouncyCastle.Compat
{
  static class Platform
  {
    internal static System.Collections.IList CreateArrayList()
    {
      return new ArrayList();
    }

    internal static System.Collections.IList CreateArrayList(int capacity)
    {
      return new ArrayList(capacity);
    }

    internal static System.Collections.IList CreateArrayList(System.Collections.ICollection collection)
    {
      return new ArrayList(collection);
    }

    internal static System.Collections.IList CreateArrayList(System.Collections.IEnumerable collection)
    {
      ArrayList result = new ArrayList();
      foreach (object o in collection)
      {
        result.Add(o);
      }

      return result;
    }

    internal static System.Collections.IDictionary CreateHashtable()
    {
      return new Hashtable();
    }
  }
}