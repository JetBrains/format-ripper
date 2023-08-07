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
      var fullResourceName = new StringBuilder(type.Namespace).Append(".Resources.").Append(category switch
        {
          ResourceCategory.MachO => "MachO",
          ResourceCategory.Msi => "Msi",
          ResourceCategory.Pe => "Pe",
          _ => new ArgumentOutOfRangeException(nameof(category), category, null)
        })
        .Append('.').Append(resourceName).ToString();
      using var stream = type.Assembly.GetManifestResourceStream(fullResourceName);
      if (stream == null)
        throw new InvalidOperationException($"Failed to open resource stream for {fullResourceName}");
      return handler(stream);
    }
  }
}