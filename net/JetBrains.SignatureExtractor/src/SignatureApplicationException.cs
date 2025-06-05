namespace JetBrains.SignatureExtractor;

public class SignatureApplicationException: Exception
{
  public SignatureApplicationException()
  {
  }

  public SignatureApplicationException(string? message) : base(message)
  {
  }

  public SignatureApplicationException(string? message, Exception? innerException) : base(message, innerException)
  {
  }
}