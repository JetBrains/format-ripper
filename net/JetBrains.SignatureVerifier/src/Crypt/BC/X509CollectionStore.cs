using System.Collections;
using System.Collections.Generic;
using System.Linq;
using JetBrains.SignatureVerifier.Crypt.BC.Compat;
using Org.BouncyCastle.Utilities.Collections;
using Org.BouncyCastle.X509;
using Org.BouncyCastle.X509.Store;

namespace JetBrains.SignatureVerifier.Crypt.BC
{
  /**
	 * A simple collection backed store.
	 */
  internal class X509CollectionStore
    : IStore<X509Certificate>
  {
    private readonly IEnumerable<X509Certificate> _local;

    /**
		 * Basic constructor.
		 *
		 * @param collection - initial contents for the store, this is copied.
		 */
    internal X509CollectionStore(
      IEnumerable<X509Certificate> collection)
    {
      _local = collection.ToList();
    }

    /**
     * Return the matches in the collection for the passed in selector.
     *
     * @param selector the selector to match against.
     * @return a possibly empty collection of matching objects.
     */
    public IEnumerable<X509Certificate> EnumerateMatches(ISelector<X509Certificate> selector)
    {
      if (selector == null)
      {
        return _local.ToList();
      }

      List<X509Certificate> result = new List<X509Certificate>();
      foreach (var obj in _local)
      {
        if (selector.Match(obj))
          result.Add(obj);
      }

      return result;
    }
  }
}