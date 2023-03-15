using System.Collections.Generic;

namespace JetBrains.FormatRipper.Impl
{
  internal static class StreamRangeUtil
  {
    internal static void Sort(List<StreamRange> sortedRanges) =>
      sortedRanges.Sort((x, y) =>
        {
          if (x.Position < y.Position) return -1;
          if (x.Position > y.Position) return 1;
          return 0;
        });

    internal static List<StreamRange> Invert(long totalSize, List<StreamRange> sortedRanges)
    {
      var invertRanges = new List<StreamRange>();
      long pos = 0;
      long size;
      foreach (var range in sortedRanges)
      {
        size = checked(range.Position - pos);
        if (size > 0)
          invertRanges.Add(new StreamRange(pos, size));
        pos = range.Position + range.Size;
      }

      size = checked(totalSize - pos);
      if (size > 0)
        invertRanges.Add(new StreamRange(pos, size));
      return invertRanges;
    }

    internal static void MergeNeighbors(List<StreamRange> orderedRanges)
    {
      for (var n = 1; n < orderedRanges.Count;)
        if (orderedRanges[n - 1].Position + orderedRanges[n - 1].Size == orderedRanges[n].Position)
        {
          var value = new StreamRange(orderedRanges[n - 1].Position, orderedRanges[n - 1].Size + orderedRanges[n].Size);
          orderedRanges.RemoveAt(n);
          orderedRanges[n - 1] = value;
        }
        else
          ++n;
    }
  }
}