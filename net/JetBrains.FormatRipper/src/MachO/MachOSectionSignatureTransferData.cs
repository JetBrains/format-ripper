namespace JetBrains.FormatRipper.MachO;

/// <summary>
/// Class that stores sufficient information to transfer the signature from one MachO section to another
/// </summary>
public class MachOSectionSignatureTransferData
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