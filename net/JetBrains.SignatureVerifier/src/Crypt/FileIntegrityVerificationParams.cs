namespace JetBrains.SignatureVerifier.Crypt;

public class FileIntegrityVerificationParams
{
  /// <summary>
  /// Allow hash mismatches if file has more than one signature
  /// </summary>
  public bool AllowHashMismatches { get; private set; }

  /// <summary>
  /// Constructs FileIntegrityVerificationParams
  /// </summary>
  /// <param name="allowHashMismatches">Allow hash mismatches if file has more than one signature.
  /// If set to 'true' at least one signature should be valid.</param>
  public FileIntegrityVerificationParams(bool allowHashMismatches = false)
  {
    AllowHashMismatches = allowHashMismatches;
  }
}