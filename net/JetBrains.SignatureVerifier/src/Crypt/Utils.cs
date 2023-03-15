using System;
using System.Text;
using JetBrains.Annotations;

namespace JetBrains.SignatureVerifier.Crypt
{
  static class Utils
  {
    public static string FlatMessages([NotNull] this Exception ex)
    {
      if (ex == null) throw new ArgumentNullException(nameof(ex));
      var sb = new StringBuilder(ex.Message);

      while (ex.InnerException is not null)
      {
        ex = ex.InnerException;
        sb.AppendLine(ex.Message);
      }

      return sb.ToString();
    }
  }
}