namespace JetBrains.FormatRipper.MachO;

public abstract class LoadCommandInfo
{
  public abstract long Offset { get; }
  public abstract uint Command { get; }
  public abstract uint CommandSize { get; }

  public abstract byte[] ToByteArray();
}