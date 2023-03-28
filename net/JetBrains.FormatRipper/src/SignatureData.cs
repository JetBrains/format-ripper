namespace JetBrains.FormatRipper
{
  public readonly struct SignatureData
  {
    public readonly byte[]? SignedBlob;
    public readonly byte[]? CmsBlob;

    public SignatureData(byte[]? signedBlob, byte[]? cmsBlob)
    {
      SignedBlob = signedBlob;
      CmsBlob = cmsBlob;
    }
  }
}