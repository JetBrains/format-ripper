namespace JetBrains.FormatRipper.MachO;

/// <summary>
/// Class that stores sufficient information to transfer the signature from one MachO section to another
/// </summary>
public class MachOSectionSignatureTransferData
{
  public uint NumberOfLoadCommands { get; internal set; }

  public uint SizeOfLoadCommands { get; internal set; }

  public uint LcCodeSignatureSize { get; internal set; }

  public uint LinkEditDataOffset { get; internal set; }

  public uint LinkEditDataSize { get; internal set; }

  public uint LastLinkeditCommandNumber { get; internal set; }

  public ulong LastLinkeditVmSize64 { get; internal set; }

  public ulong LastLinkeditFileSize64 { get; internal set; }

  public uint LastLinkeditVmSize32 { get; internal set; }

  public uint LastLinkeditFileSize32 { get; internal set; }

  public byte[] SignatureBlob { get; internal set; }
}