namespace JetBrains.FormatRipper;

public class DataValue
{
  public readonly long Offset;

  public readonly byte[]? Value;

  public DataValue(long offset = 0, byte[]? value = null)
  {
    Offset = offset;
    Value = value;
  }
}