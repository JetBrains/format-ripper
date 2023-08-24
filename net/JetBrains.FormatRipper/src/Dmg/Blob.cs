using JetBrains.FormatRipper.Impl;

namespace JetBrains.FormatRipper.Dmg;

public class Blob
{
  public readonly uint type;
  public readonly uint offset;
  public readonly CSMAGIC_CONSTS magic;
  private uint magicValue;
  public int length;
  public byte[] content;

  public Blob(uint type, uint offset, CSMAGIC_CONSTS magic, uint magicValue, byte[] content, int? length = null)
  {
    this.type = type;
    this.offset = offset;
    this.magic = magic;
    this.magicValue = magicValue;
    this.length = length ?? content.Length;
    this.content = content;
  }

  public byte[] ToByteArray() =>
    MemoryUtil.ArrayMerge(
      MemoryUtil.ToByteArray(magicValue, true),
      MemoryUtil.ToByteArray(length, true),
      content
    );
}