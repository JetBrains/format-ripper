using JetBrains.FormatRipper.Impl;

namespace JetBrains.FormatRipper.MachO;

public class MachoHeaderMetainfo
{
  public uint Magic { get; set; } = 0;
  public uint CpuType { get; set; } = 0;
  public uint CpuSubType { get; set; } = 0;
  public uint FileType { get; set; } = 0;
  public uint NumLoadCommands { get; set; } = 0;
  public uint SizeLoadCommands { get; set; } = 0;
  public uint Flags { get; set; } = 0;
  public uint Reserved { get; set; } = 0;

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