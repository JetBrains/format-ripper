namespace JetBrains.FormatRipper.MachO;

/// <summary>
/// Class that stores sufficient information to transfer the signature from one MachO file to another
/// </summary>
public class MachOSignatureTransferData
{
  /// <summary>
  /// Signatures of sections
  /// </summary>
  public MachOSectionSignatureTransferData?[] SectionSignatures { get; internal set; }

  public MachOSignatureTransferData(MachOSectionSignatureTransferData?[] sectionSignatures)
  {
    SectionSignatures = sectionSignatures;
  }
}