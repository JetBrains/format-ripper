using System;
using JetBrains.FormatRipper.Impl;

namespace JetBrains.FormatRipper.MachO.Impl;

public abstract class FatArchInfo
{
  public uint CpuType;
  public uint CpuSubType;

  public abstract byte[] ToByteArray(bool isBe);
}

public class FatArchInfo64 : FatArchInfo
{
  public ulong FileOffset;
  public ulong Size;
  public ulong Align;

  public FatArchInfo64(uint cpuType, uint cpuSubType, ulong fileOffset, ulong size, ulong align)
  {
    CpuType = cpuType;
    CpuSubType = cpuSubType;
    FileOffset = fileOffset;
    Size = size;
    Align = align;
  }

  public override byte[] ToByteArray(bool isBe) => MemoryUtil.ArrayMerge(
    MemoryUtil.ToByteArray(CpuType, isBe),
    MemoryUtil.ToByteArray(CpuSubType, isBe),
    MemoryUtil.ToByteArray((long)FileOffset, isBe),
    MemoryUtil.ToByteArray((long)Size, isBe),
    MemoryUtil.ToByteArray((long)Align, isBe)
  );
}

public class FatArchInfo32 : FatArchInfo
{
  public uint FileOffset;
  public uint Size;
  public uint Align;

  public FatArchInfo32(uint cpuType, uint cpuSubType, uint fileOffset, uint size, uint align)
  {
    CpuType = cpuType;
    CpuSubType = cpuSubType;
    FileOffset = fileOffset;
    Size = size;
    Align = align;
  }

  public override byte[] ToByteArray(bool isBe) => MemoryUtil.ArrayMerge(
    MemoryUtil.ToByteArray(CpuType, isBe),
    MemoryUtil.ToByteArray(CpuSubType, isBe),
    MemoryUtil.ToByteArray(FileOffset, isBe),
    MemoryUtil.ToByteArray(Size, isBe),
    MemoryUtil.ToByteArray(Align, isBe)
  );
}