using System;
using JetBrains.SignatureVerifier;

namespace JetBrains.Serialization.Tests
{
  internal sealed class ConsoleLogger : ILogger
  {
    public static readonly ILogger Instance = new ConsoleLogger();

    private ConsoleLogger()
    {
    }

    void ILogger.Info(string str) => Console.WriteLine($"INFO: {str}");
    void ILogger.Warning(string str) => Console.Error.WriteLine($"WARNING: {str}");
    void ILogger.Error(string str) => Console.Error.WriteLine($"ERROR: {str}");
    void ILogger.Trace(string str) => Console.Error.WriteLine($"TRACE: {str}");
  }
}