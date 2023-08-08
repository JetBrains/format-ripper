namespace JetBrains.FormatRipper;

public class DataValue
{
  public long Offset { get; }

  public byte[]? Value { get; }

  public DataValue(long offset = 0, byte[]? value = null)
  {
    Offset = offset;
    Value = value;
  }
}