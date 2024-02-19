namespace JetBrains.FormatRipper.MachO;

public class MachOFileSignature
{
  public MachOSectionSignature?[] SectionSignatures { get; internal set; }

  public MachOFileSignature(MachOSectionSignature?[] sectionSignatures)
  {
    SectionSignatures = sectionSignatures;
  }
}