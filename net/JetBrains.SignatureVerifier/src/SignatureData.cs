using JetBrains.FormatRipper.MachO;

namespace JetBrains.SignatureVerifier
{
  public readonly struct SignatureData
  {
    public SignatureData(MachOFile.Section section) :
      this(section.CodeDirectoryBlob, section.CmsSignatureBlob)
    {
    }

    public SignatureData(byte[] signedData, byte[] cmsData)
    {
      SignedData = signedData;
      CmsData = cmsData;
    }

    /// <summary>
    /// Signed data
    /// </summary>
    public byte[] SignedData { get; }

    /// <summary>
    ///Cryptographic Message Syntax data
    /// </summary>
    public byte[] CmsData { get; }

    public bool IsEmpty => CmsData is null;
    public bool HasAttachedSignedData => SignedData is not null;

    public static SignatureData Empty = new(null, null);
  }
}