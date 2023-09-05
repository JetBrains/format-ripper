using JetBrains.FormatRipper.MachO;

namespace JetBrains.Serialization.FileInfos.MachO;

public class MachoArchInfo
{
  private List<MachoFileInfo> _fileInfos = new List<MachoFileInfo>();
  private FatHeaderInfo? _headerInfo;

  public MachoArchInfo(MachOFile file)
  {
    _headerInfo = file.FatHeaderInfo;
    foreach (var fileSection in file.Sections)
    {
      _fileInfos.Add(new MachoFileInfo(fileSection));
    }
  }
}