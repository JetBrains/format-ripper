using System;

namespace JetBrains.FormatRipper.MachO;

public class LoadCommandSignatureInfo : LoadCommandInfo
{
  public override long Offset { get; }
  public override uint Command { get; }
  public override uint CommandSize { get; }
  public uint DataOffset { get; set; }
  public uint DataSize { get; set; }

  public LoadCommandSignatureInfo(long offset, uint command, uint commandSize, uint dataOffset, uint dataSize)
  {
    Offset = offset;
    Command = command;
    CommandSize = commandSize;
    DataOffset = dataOffset;
    DataSize = dataSize;
  }

  public override byte[] ToByteArray()
  {
    throw new NotImplementedException();
  }
}