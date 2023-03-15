using JetBrains.Annotations;

namespace JetBrains.SignatureVerifier
{
  public interface ILogger
  {
    void Info([NotNull] string str);
    void Warning([NotNull] string str);
    void Error([NotNull] string str);
    void Trace([NotNull] string str);
  }
}