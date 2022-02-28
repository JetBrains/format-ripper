using System.Diagnostics;

namespace JetBrains.SignatureVerifier
{
  [DebuggerDisplay("{Offset} {Size}")]
  readonly struct DataInfo
  {
    public DataInfo(int offset, int size)
    {
      Offset = offset;
      Size = size;
    }

    public bool IsEmpty => Offset == 0 && Size == 0;
    public int Offset { get; }
    public int Size { get; }

    public override string ToString()
    {
      return $"{nameof(Offset)}: {Offset}, {nameof(Size)}: {Size}";
    }
  }
}