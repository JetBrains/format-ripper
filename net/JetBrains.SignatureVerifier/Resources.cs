using System;
using System.IO;
using System.Reflection;
using JetBrains.Annotations;

namespace JetBrains.SignatureVerifier
{
    public static class Resources
    {
        public static Stream GetDefaultRoots() => GetResourceStream("DefaultRoots.p7b");

        static Stream GetResourceStream([NotNull] string resourceName)
        {
            var type = typeof(Resources);
            return type.Assembly.OpenStreamFromResource($"{type.Namespace}.{resourceName}");
        }
        
        static Stream OpenStreamFromResource([NotNull] this Assembly assembly, [NotNull] string resourceName)
        {
            if (assembly == null) throw new ArgumentNullException(nameof(assembly));
            var stream = assembly.GetManifestResourceStream(resourceName);
            if (stream == null)
                throw new InvalidOperationException($"Failed to open resource stream for {resourceName}");
            return stream;
        }
    }
}