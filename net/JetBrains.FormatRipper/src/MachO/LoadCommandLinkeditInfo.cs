using System;
using JetBrains.FormatRipper.Impl;

namespace JetBrains.FormatRipper.MachO;

public class LoadCommandLinkeditInfo : LoadCommandInfo
{
  public override long Offset { get; }
  public override uint Command { get; }
  public override uint CommandSize { get; }
  public byte[] SegmentName { get; set; }
  public ulong VmAddress { get; set; }
  public ulong VmSize { get; set; }
  public ulong VmFileOff { get; set; }
  public ulong FileSize { get; set; }
  public uint VmProcMaximumProtection { get; set; }
  public uint VmProcInitialProtection { get; set; }
  public uint SectionsNum { get; set; }
  public uint SegmentFlags { get; set; }

  public LoadCommandLinkeditInfo(long offset, uint command, uint commandSize, byte[] segmentName, ulong vmAddress,
    ulong vmSize, ulong vmFileOff, ulong fileSize, uint vmProcMaximumProtection, uint vmProcInitialProtection,
    uint sectionsNum, uint segmentFlags)
  {
    Offset = offset;
    Command = command;
    CommandSize = commandSize;
    SegmentName = segmentName;
    VmAddress = vmAddress;
    VmSize = vmSize;
    VmFileOff = vmFileOff;
    FileSize = fileSize;
    VmProcMaximumProtection = vmProcMaximumProtection;
    VmProcInitialProtection = vmProcInitialProtection;
    SectionsNum = sectionsNum;
    SegmentFlags = segmentFlags;
  }

  public override byte[] ToByteArray() =>
    MemoryUtil.ArrayMerge(
      MemoryUtil.ToByteArray(Command),
      MemoryUtil.ToByteArray(CommandSize),
      SegmentName,
      MemoryUtil.ToByteArray((long)VmAddress),
      MemoryUtil.ToByteArray((long)VmSize),
      MemoryUtil.ToByteArray((long)VmFileOff),
      MemoryUtil.ToByteArray((long)FileSize),
      MemoryUtil.ToByteArray(VmProcMaximumProtection),
      MemoryUtil.ToByteArray(VmProcInitialProtection),
      MemoryUtil.ToByteArray(SectionsNum),
      MemoryUtil.ToByteArray(SegmentFlags)
    );
}