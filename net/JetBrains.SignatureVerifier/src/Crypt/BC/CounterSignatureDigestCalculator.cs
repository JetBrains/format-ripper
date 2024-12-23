using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;

namespace JetBrains.SignatureVerifier.Crypt.BC
{
  internal class CounterSignatureDigestCalculator
    : IDigestCalculator
  {
    private readonly string alg;
    private readonly byte[] data;

    internal CounterSignatureDigestCalculator(
      string alg,
      byte[] data)
    {
      this.alg = alg;
      this.data = data;
    }

    public byte[] GetDigest()
    {
      IDigest digest = CmsSignedHelper.Instance.GetDigestInstance(alg);
      return DigestUtilities.DoFinal(digest, data);
    }
  }
}