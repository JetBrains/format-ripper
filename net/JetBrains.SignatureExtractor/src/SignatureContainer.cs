using JetBrains.FormatRipper.Dmg;
using JetBrains.FormatRipper.FileExplorer;
using JetBrains.FormatRipper.MachO;
using JetBrains.FormatRipper.Pe;
using Newtonsoft.Json.Serialization;

namespace JetBrains.SignatureExtractor;

record SignatureContainer(FileType FileType, IMachOSignatureTransferData? MachOSignatureTransferData, IPeSignatureTransferData? PeSignatureTransferData, IDmgSignatureTransferData? DmgSignatureTransferData);

internal class DmgSignatureTransferData: IDmgSignatureTransferData
{
  public long SignatureOffset { get; set; }

  public long SignatureLength { get; set; }

  public byte[] SignatureBlob { get; set; } = null!;
}

internal class MachOSignatureTransferData: IMachOSignatureTransferData
{
  public IMachOSectionSignatureTransferData?[] SectionSignatures { get; set; } = null!;
}

internal class MachOSectionSignatureTransferData: IMachOSectionSignatureTransferData
{
  public uint NumberOfLoadCommands { get; set; }

  public uint SizeOfLoadCommands { get; set; }

  public uint LcCodeSignatureSize { get; set; }

  public uint LinkEditDataOffset { get; set; }

  public uint LinkEditDataSize { get; set; }

  public uint LastLinkeditCommandNumber { get; set; }

  public ulong LastLinkeditVmSize64 { get; set; }

  public ulong LastLinkeditFileSize64 { get; set; }

  public uint LastLinkeditVmSize32 { get; set; }

  public uint LastLinkeditFileSize32 { get; set; }

  public byte[] SignatureBlob { get; set; } = null!;
}

internal class PeSignatureTransferData: IPeSignatureTransferData
{
  public uint CheckSum { get; set; }

  public uint TimeDateStamp { get; set; }

  public uint SignatureBlobOffset { get; set; }

  public uint SignatureBlobSize { get; set; }

  public ushort CertificateRevision { get; set; }

  public ushort CertificateType { get; set; }

  public byte[] SignatureBlob { get; set; } = null!;
}

public class SignatureContainerContractResolver : DefaultContractResolver
{
  protected override JsonObjectContract CreateObjectContract(Type objectType)
  {
    if (objectType.IsInterface)
    {
      if (objectType == typeof(IMachOSectionSignatureTransferData))
        return base.CreateObjectContract(typeof(MachOSectionSignatureTransferData));
      else if (objectType == typeof(IMachOSignatureTransferData))
        return base.CreateObjectContract(typeof(MachOSignatureTransferData));
      else if (objectType == typeof(IPeSignatureTransferData))
        return base.CreateObjectContract(typeof(PeSignatureTransferData));
      else if (objectType == typeof(IDmgSignatureTransferData))
        return base.CreateObjectContract(typeof(DmgSignatureTransferData));
    }

    return base.CreateObjectContract(objectType);
  }
}