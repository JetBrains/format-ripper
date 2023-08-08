using System;
using System.IO;
using System.Text;

namespace JetBrains.Serialization.Tests
{
  internal static class ResourceUtil
  {
    internal static TResult OpenRead<TResult>(ResourceCategory category, string resourceName,
      Func<Stream, TResult> handler)
    {
      var type = typeof(ResourceUtil);
      var fullResourceName = GetPath(category, resourceName);
      using var stream = type.Assembly.GetManifestResourceStream(fullResourceName);
      if (stream == null)
        throw new InvalidOperationException($"Failed to open resource stream for {fullResourceName}");
      return handler(stream);
    }

    internal static string GetPath(ResourceCategory category, string resourceName) =>
      new StringBuilder(typeof(ResourceUtil).Namespace)
        .Append(".Resources.").Append(category switch
        {
          ResourceCategory.MachO => "MachO",
          ResourceCategory.Msi => "Msi",
          ResourceCategory.Pe => "Pe",
          _ => new ArgumentOutOfRangeException(nameof(category), category, null)
        })
        .Append('.').Append(resourceName).ToString();


    internal static bool CompareTwoStreams(Stream stream1, Stream stream2)
    {
      const int bufferSize = 1024 * sizeof(long);
      byte[] buffer1 = new byte[bufferSize];
      byte[] buffer2 = new byte[bufferSize];

      while (true)
      {
        int count1 = stream1.Read(buffer1, 0, bufferSize);
        int count2 = stream2.Read(buffer2, 0, bufferSize);

        if (count1 != count2)
        {
          return false;
        }

        if (count1 == 0 && count2 == 0)
        {
          return true;
        }

        if (!buffer1.SequenceEqual(buffer2))
        {
          return false;
        }
      }
    }
  }
}