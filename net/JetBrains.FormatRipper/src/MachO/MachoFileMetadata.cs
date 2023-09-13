using System.Collections.Generic;

namespace JetBrains.FormatRipper.MachO;

public class MachoFileMetadata
{
  public long MachoOffset;
  public long FileSize;
  public bool IsBe;
  public MachoHeaderMetainfo HeaderMetainfo;
  public readonly List<LoadCommandInfo> LoadCommands;
  public readonly CodeSignatureInfo CodeSignatureInfo;

  public MachoFileMetadata(long machoOffset, long fileSize, bool isBe, MachoHeaderMetainfo? headerMetainfo = null,
    List<LoadCommandInfo>? loadCommands = null, CodeSignatureInfo? codeSignatureInfo = null)
  {
    MachoOffset = machoOffset;
    FileSize = fileSize;
    IsBe = isBe;
    HeaderMetainfo = headerMetainfo ?? new MachoHeaderMetainfo();
    LoadCommands = loadCommands ?? new List<LoadCommandInfo>();
    CodeSignatureInfo = codeSignatureInfo ?? new CodeSignatureInfo();
  }
}