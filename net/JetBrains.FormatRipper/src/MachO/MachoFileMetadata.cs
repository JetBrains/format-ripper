using System.Collections.Generic;

namespace JetBrains.FormatRipper.MachO;

public class MachoFileMetadata
{
  public long MachoOffset { get; }
  public long FileSize { get; }
  public bool IsBe { get; }
  public MachoHeaderMetainfo HeaderMetainfo { get; }
  public List<LoadCommandInfo> LoadCommands { get; }
  public CodeSignatureInfo CodeSignatureInfo { get; }
}