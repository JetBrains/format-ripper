using System;

namespace JetBrains.FormatRipper;

public class SignatureInjectionException: Exception
{
  internal SignatureInjectionException(string message) : base(message)
  {
  }

  internal SignatureInjectionException(string message, Exception innerException) : base(message, innerException)
  {
  }
}