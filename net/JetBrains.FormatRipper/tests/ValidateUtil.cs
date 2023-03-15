using NUnit.Framework;

namespace JetBrains.FormatRipper.Tests
{
  internal static class ValidateUtil
  {
    internal static void Validate(ComputeHashInfo info, string? message = null)
    {
      Assert.LessOrEqual(0, info.Offset, message);
      Assert.LessOrEqual(0, info.ZeroPadding, message);
      long pos = -1;
      foreach (var range in info.OrderedIncludeRanges)
      {
        Assert.LessOrEqual(0, range.Position, message);
        Assert.Less(0, range.Size, message);
        Assert.Less(pos, range.Position, message);
        pos = range.Position + range.Size;
      }
    }
  }
}