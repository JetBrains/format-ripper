namespace JetBrains.SignatureVerifier
{
  public readonly struct SignatureData
  {
    public SignatureData(byte[] signedData, byte[] cmsData)
    {
      SignedData = signedData;
      CmsData = cmsData;
    }

    public byte[] SignedData { get; }
    public byte[] CmsData { get; }
    public bool IsEmpty => SignedData is null;
  }
}