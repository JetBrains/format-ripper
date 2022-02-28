namespace JetBrains.SignatureVerifier
{
  public sealed class NullLogger : ILogger
  {
    public static readonly ILogger Instance = new NullLogger();

    private NullLogger()
    {
    }

    void ILogger.Info(string str)
    {
    }

    void ILogger.Warning(string str)
    {
    }

    void ILogger.Error(string str)
    {
    }

    void ILogger.Trace(string str)
    {
    }
  }
}