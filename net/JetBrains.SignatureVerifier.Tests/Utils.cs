using System;
using System.IO;
using System.Reflection;
using JetBrains.Annotations;

namespace JetBrains.SignatureVerifier.Tests
{
    static class Utils
    {
        internal static TResult StreamFromResource<TResult>([NotNull] string resourceName, [NotNull] Func<Stream, TResult> handler)
        {
            var type = typeof(PeSignatureVerifierTests);
            return type.Assembly.OpenStreamFromResource(type.Namespace + ".Resources." + resourceName, handler);
        }
        
        private static TResult OpenStreamFromResource<TResult>([NotNull] this Assembly assembly, [NotNull] string resourceName, [NotNull] Func<Stream, TResult> handler)
        {
            if (assembly == null) throw new ArgumentNullException(nameof(assembly));
            if (handler == null) throw new ArgumentNullException(nameof(handler));
            using var stream = assembly.GetManifestResourceStream(resourceName);
            if (stream == null)
                throw new InvalidOperationException($"Failed to open resource stream for {resourceName}");
            return handler(stream);
        }

        internal static string ConvertToHexString(byte[] data) => BitConverter.ToString(data).Replace("-", "");
    }
}