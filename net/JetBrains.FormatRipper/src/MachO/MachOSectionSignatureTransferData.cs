namespace JetBrains.FormatRipper.MachO;

/// <summary>
/// Interface that has sufficient information to transfer the signature from one MachO section to another
/// </summary>
public interface IMachOSectionSignatureTransferData
{
  uint NumberOfLoadCommands { get; }

  uint SizeOfLoadCommands { get; }

  uint LcCodeSignatureSize { get; }

  uint LinkEditDataOffset { get; }

  uint LinkEditDataSize { get; }

  uint LastLinkeditCommandNumber { get; }

  ulong LastLinkeditVmSize64 { get; }

  ulong LastLinkeditFileSize64 { get; }

  uint LastLinkeditVmSize32 { get; }

  uint LastLinkeditFileSize32 { get; }

  byte[] SignatureBlob { get; }
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