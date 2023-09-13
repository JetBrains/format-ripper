using System;
using JetBrains.FormatRipper.Impl;

namespace JetBrains.FormatRipper.MachO;

public class LoadCommandSignatureInfo : LoadCommandInfo
{
  public override long Offset { get; }
  public override uint Command { get; }
  public override uint CommandSize { get; }
  public readonly uint DataOffset;
  public readonly uint DataSize;

  public LoadCommandSignatureInfo(long offset, uint command, uint commandSize, uint dataOffset, uint dataSize)
  {
    Offset = offset;
    Command = command;
    CommandSize = commandSize;
    DataOffset = dataOffset;
    DataSize = dataSize;
  }

  public override byte[] ToByteArray() =>
    MemoryUtil.ArrayMerge(
      MemoryUtil.ToByteArray(Command),
      MemoryUtil.ToByteArray(CommandSize),
      MemoryUtil.ToByteArray(DataOffset),
      MemoryUtil.ToByteArray(DataSize)
    );
}