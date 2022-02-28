using System.Collections.Generic;
using Org.BouncyCastle.X509;

namespace JetBrains.SignatureVerifier.Crypt
{
  public class X509CertificateEquComparer : IEqualityComparer<X509Certificate>
  {
    public bool Equals(X509Certificate x, X509Certificate y)
    {
      if (ReferenceEquals(x, y)) return true;
      if (ReferenceEquals(x, null)) return false;
      if (ReferenceEquals(y, null)) return false;
      if (x.GetType() != y.GetType()) return false;
      return x.SerialNumber.Equals(y.SerialNumber) && x.IssuerDN.Equivalent(y.IssuerDN);
    }

    public int GetHashCode(X509Certificate obj)
    {
      unchecked
      {
        return (obj.SerialNumber.GetHashCode() * 397) ^ obj.IssuerDN.GetHashCode();
      }
    }
  }
}