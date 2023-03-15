namespace JetBrains.SignatureVerifier.Crypt
{
  public class VerifySignatureResult
  {
    private readonly VerifySignatureStatus _status;
    public VerifySignatureStatus Status => _status;
    public bool NotValid => _status != VerifySignatureStatus.Valid;
    public string Message { get; set; }
    public static readonly VerifySignatureResult Valid = new(VerifySignatureStatus.Valid);

    public VerifySignatureResult(VerifySignatureStatus status)
    {
      _status = status;
    }

    public static VerifySignatureResult InvalidChain(string message) =>
      new(VerifySignatureStatus.InvalidChain)
        { Message = message };
  }

  public enum VerifySignatureStatus
  {
    Valid,
    InvalidSignature,
    InvalidChain,
    InvalidTimestamp
  }
}