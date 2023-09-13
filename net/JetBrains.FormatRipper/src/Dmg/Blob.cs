using JetBrains.FormatRipper.Impl;

namespace JetBrains.FormatRipper.Dmg;

public class Blob
{
  public readonly uint Type;
  public readonly uint Offset;
  public readonly CSMAGIC_CONSTS Magic;
  public readonly uint MagicValue;
  public int Length;
  public byte[] Content;

  public Blob(uint type, uint offset, CSMAGIC_CONSTS magic, uint magicValue, byte[] content, int? length = null)
  {
    Type = type;
    Offset = offset;
    Magic = magic;
    MagicValue = magicValue;
    Length = length ?? content.Length;
    Content = content;
  }

  public byte[] ToByteArray() =>
    MemoryUtil.ArrayMerge(
      MemoryUtil.ToByteArray(MagicValue, true),
      MemoryUtil.ToByteArray(Length, true),
      Content
    );
}