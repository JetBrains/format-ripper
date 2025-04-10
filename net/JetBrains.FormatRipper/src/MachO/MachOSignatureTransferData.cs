namespace JetBrains.FormatRipper.MachO;

/// <summary>
/// Interface that has sufficient information to transfer the signature from one MachO file to another
/// </summary>
public interface IMachOSignatureTransferData
{
  /// <summary>
  /// Signatures of sections
  /// </summary>
  public IMachOSectionSignatureTransferData?[] SectionSignatures { get; }
}

internal class MachOSignatureTransferData: IMachOSignatureTransferData
{
  public IMachOSectionSignatureTransferData?[] SectionSignatures { get; set; }

  public MachOSignatureTransferData(IMachOSectionSignatureTransferData?[] sectionSignatures)
  {
    SectionSignatures = sectionSignatures;
  }
}