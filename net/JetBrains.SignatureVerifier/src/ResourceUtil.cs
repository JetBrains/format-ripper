using System;
using System.IO;
using JetBrains.Annotations;

namespace JetBrains.SignatureVerifier
{
  public static class ResourceUtil
  {
    public static TResult OpenDefaultRoots<TResult>([NotNull] Func<Stream, TResult> handler) => OpenRead("DefaultRoots.p7b", handler);

    private static TResult OpenRead<TResult>(string resourceName, Func<Stream, TResult> handler)
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