using System.Collections.Generic;
using Org.BouncyCastle.X509;

namespace JetBrains.SignatureVerifier.Crypt
{
  class X509CrlEquComparer : IEqualityComparer<X509Crl>
  {
    public bool Equals(X509Crl x, X509Crl y)
    {
      if (ReferenceEquals(x, y)) return true;
      if (ReferenceEquals(x, null)) return false;
      if (ReferenceEquals(y, null)) return false;
      if (x.GetType() != y.GetType()) return false;
      return Equals(x.IssuerDN, y.IssuerDN);
    }

    public int GetHashCode(X509Crl obj)
    {
      return (obj.IssuerDN is not null ? obj.IssuerDN.GetHashCode() : 0);
    }
  }
}