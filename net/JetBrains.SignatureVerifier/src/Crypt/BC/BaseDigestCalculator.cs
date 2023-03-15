using Org.BouncyCastle.Utilities;

namespace JetBrains.SignatureVerifier.Crypt.BC
{
  internal class BaseDigestCalculator
    : IDigestCalculator
  {
    private readonly byte[] digest;

    internal BaseDigestCalculator(
      byte[] digest)
    {
      this.digest = digest;
    }

    public byte[] GetDigest()
    {
      return Arrays.Clone(digest);
    }
  }
}