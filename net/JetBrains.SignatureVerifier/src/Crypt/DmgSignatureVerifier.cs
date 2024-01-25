using System;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using JetBrains.Annotations;
using JetBrains.FormatRipper.Dmg;
using JetBrains.FormatRipper.MachO;

namespace JetBrains.SignatureVerifier.Crypt;

/// <summary>
/// DMG format signatures verifier
/// </summary>
public class DmgSignatureVerifier: AppleSignatureVerifier
{
  /// <summary>
  /// Constructs new verifier
  /// </summary>
  /// <param name="logger">Logger</param>
  public DmgSignatureVerifier([CanBeNull] ILogger logger) : base(logger)
  {
  }

  /// <summary>
  /// Constructs new verifier
  /// </summary>
  /// <param name="signedMessageVerifier">Signed message verifier</param>
  /// <param name="logger">Logger</param>
  public DmgSignatureVerifier([NotNull] SignedMessageVerifier signedMessageVerifier, [CanBeNull] ILogger logger) : base(signedMessageVerifier, logger)
  {
  }

  /// <summary>
  /// Verify digital signature and file integrity of a DMG file
  /// </summary>
  /// <param name="dmgFile">DMG file</param>
  /// <param name="stream">DMG file raw stream</param>
  /// <param name="signatureVerificationParams">Verification params</param>
  /// <param name="fileIntegrityVerificationParams">File integrity verification params</param>
  /// <returns>Verification result</returns>
  public async Task<VerifySignatureResult> VerifyAsync(
    DmgFile dmgFile,
    Stream stream,
    SignatureVerificationParams signatureVerificationParams,
    FileIntegrityVerificationParams fileIntegrityVerificationParams)
  {
    if (!dmgFile.HasSignature)
    {
      _logger?.Warning("DMG file signature verification failed: file is not signed");
      return new VerifySignatureResult(VerifySignatureStatus.InvalidSignature);
    }

    if (!dmgFile.HashVerificationUnits.Any() || !dmgFile.CDHashes.Any())
      throw new ArgumentException($"DMG file was parsed without {nameof(DmgFile.Mode.ComputeHashInfo)} flag", nameof(dmgFile));

    var signedMessage = SignedMessage.CreateInstance(dmgFile.SignatureData);
    var signatureVerificationResult = await _signedMessageVerifier.VerifySignatureAsync(signedMessage, signatureVerificationParams);

    if (!signatureVerificationResult.IsValid)
    {
      _logger?.Warning("DMG file signature verification failed: certificates or attributes validation failed");
      return signatureVerificationResult;
    }

    if (!dmgFile.HashVerificationUnits.Any())
    {
      _logger?.Warning("DMG file signature verification failed: no hash verification units was found in the file");
      return new VerifySignatureResult(VerifySignatureStatus.InvalidFileHash);
    }

    // Verify hash slots (regular and special) in all Code Directories
    var codeDirectoryValidationResult = VerifyHashVerificationUnits(stream, dmgFile.HashVerificationUnits);

    if (!codeDirectoryValidationResult.IsValid)
    {
      _logger?.Warning("DMG file signature verification failed: at least one hash verification unit is invalid");
      return codeDirectoryValidationResult;
    }

    if (!dmgFile.CDHashes.Any())
    {
      _logger?.Warning("DMG file signature verification failed: no code directory hashes (CDHash) was found in the file");
      return new VerifySignatureResult(VerifySignatureStatus.InvalidFileHash);
    }

    if (dmgFile.CDHashes.Count() > 1)
    {
      var cdHashesVerificationResult = VerifyCDHashes(stream, dmgFile.CDHashes, signedMessage);

      if (!cdHashesVerificationResult.IsValid)
      {
        _logger?.Warning("DMG file signature verification failed: at leash one CDHash verification failed");
        return cdHashesVerificationResult;
      }
    }

    _logger?.Info("DMG file signature verification successfully passed");

    return VerifySignatureResult.Valid;
  }
}