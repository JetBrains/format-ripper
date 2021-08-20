namespace JetBrains.SignatureVerifier.Crypt.BC
{
    /// <summary>
    /// Borrowed from Org.BouncyCastle.Cms.IDigestCalculator
    /// </summary>
    internal interface IDigestCalculator
    {
        byte[] GetDigest();
    }
}