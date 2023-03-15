namespace JetBrains.SignatureVerifier.Crypt.BC
{
  internal interface IDigestCalculator
  {
    byte[] GetDigest();
  }
}