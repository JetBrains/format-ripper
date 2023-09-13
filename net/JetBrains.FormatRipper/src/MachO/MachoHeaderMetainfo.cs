using JetBrains.FormatRipper.Impl;

namespace JetBrains.FormatRipper.MachO;

public class MachoHeaderMetainfo
{
  public readonly uint Magic;
  public readonly uint CpuType;
  public readonly uint CpuSubType;
  public readonly uint FileType;
  public readonly uint NumLoadCommands;
  public readonly uint SizeLoadCommands;
  public readonly uint Flags;
  public readonly uint Reserved;

  public MachoHeaderMetainfo(uint magic = 0, uint cpuType = 0, uint cpuSubType = 0, uint fileType = 0,
    uint numLoadCommands = 0, uint sizeLoadCommands = 0, uint flags = 0, uint reserved = 0)
  {
    Magic = magic;
    CpuType = cpuType;
    CpuSubType = cpuSubType;
    FileType = fileType;
    NumLoadCommands = numLoadCommands;
    SizeLoadCommands = sizeLoadCommands;
    Flags = flags;
    Reserved = reserved;
  }

  public byte[] ToByteArray(bool isBe) => MemoryUtil.ArrayMerge(
    MemoryUtil.ToByteArray(Magic, isBe),
    MemoryUtil.ToByteArray(CpuType, isBe),
    MemoryUtil.ToByteArray(CpuSubType, isBe),
    MemoryUtil.ToByteArray(FileType, isBe),
    MemoryUtil.ToByteArray(NumLoadCommands, isBe),
    MemoryUtil.ToByteArray(SizeLoadCommands, isBe),
    MemoryUtil.ToByteArray(Flags, isBe),
    MemoryUtil.ToByteArray(Reserved, isBe)
  );
}