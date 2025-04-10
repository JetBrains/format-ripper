namespace SignatureExtractor;

public class SignatureExtractionException: Exception
{
  public SignatureExtractionException()
  {
  }

  public SignatureExtractionException(string? message) : base(message)
  {
  }

  public SignatureExtractionException(string? message, Exception? innerException) : base(message, innerException)
  {
  }
}
