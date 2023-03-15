using System;
using System.IO;

namespace JetBrains.FormatRipper.Tests
{
  internal static class ResourceUtil
  {
    internal static TResult OpenRead<TResult>(string resourceName, Func<Stream, TResult> handler)
    {
      var type = typeof(ResourceUtil);
      var fullResourceName = type.Namespace + ".Resources." + resourceName;
      using var stream = type.Assembly.GetManifestResourceStream(fullResourceName);
      if (stream == null)
        throw new InvalidOperationException($"Failed to open resource stream for {fullResourceName}");
      return handler(stream);
    }
  }
}