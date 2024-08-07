using System;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using JetBrains.Annotations;
using JetBrains.FormatRipper.MachO;

namespace JetBrains.SignatureVerifier.Crypt;

/// <summary>
/// Mach-o format signatures verifier
/// </summary>
public class MachOSignatureVerifier: AppleSignatureVerifier
{
  /// <summary>
  /// Constructs new verifier
  /// </summary>
  /// <param name="logger">Logger</param>
  public MachOSignatureVerifier([CanBeNull] ILogger logger) : base(logger)
  {
  }

  /// <summary>
  /// Constructs new verifier
  /// </summary>
  /// <param name="signedMessageVerifier">Signed message verifier</param>
  /// <param name="logger">Logger</param>
  public MachOSignatureVerifier([NotNull] SignedMessageVerifier signedMessageVerifier, [CanBeNull] ILogger logger): base(signedMessageVerifier, logger)
  {
  }

  /// <summary>
  /// Verify digital signature and file integrity of a Mach-o file
  /// </summary>
  /// <param name="machOFile">Parsed Mach-o file</param>
  /// <param name="stream">Mach-o file raw stream</param>
  /// <param name="signatureVerificationParams">Verification params</param>
  /// <param name="fileIntegrityVerificationParams">File integrity verification params</param>
  /// <returns>Verification result</returns>
  public async Task<VerifySignatureResult> VerifyAsync(
    [NotNull] MachOFile machOFile,
    [NotNull] Stream stream,
    SignatureVerificationParams signatureVerificationParams,
    FileIntegrityVerificationParams fileIntegrityVerificationParams)
  {
    if (machOFile == null) throw new ArgumentNullException(nameof(machOFile));
    if (stream == null) throw new ArgumentNullException(nameof(stream));

    foreach (var section in machOFile.Sections)
    {
      var sectionVerificationResult = await VerifyAsync(section, stream, signatureVerificationParams, fileIntegrityVerificationParams);

      if (!sectionVerificationResult.IsValid)
        return sectionVerificationResult;
    }

    _logger?.Info("Mach-O file signature verification successfully passed");

    return VerifySignatureResult.Valid;
  }

  /// <summary>
  /// Verify digital signature and file integrity of a single Mach-o file section
  /// </summary>
  /// <param name="section">Mach-o file section</param>
  /// <param name="stream">Mach-o file raw stream. A stream of the entire file is expected.</param>
  /// <param name="signatureVerificationParams">Verification params</param>
  /// <param name="fileIntegrityVerificationParams">File integrity verification params</param>
  /// <returns>Verification result</returns>
  public async Task<VerifySignatureResult> VerifyAsync(
    MachOFile.Section section,
    Stream stream,
    SignatureVerificationParams signatureVerificationParams,
    FileIntegrityVerificationParams fileIntegrityVerificationParams)
  {
    if (!section.HashVerificationUnits.Any() || !section.CDHashes.Any())
      throw new ArgumentException($"Mach-o file was parsed without {nameof(MachOFile.Mode.ComputeHashInfo)} flag", nameof(section));

    if (section.SignatureType == MachOFile.SignatureType.AdHoc && !signatureVerificationParams.AllowAdhocSignatures)
    {
      _logger?.Warning($"Mach-O file has adhoc signature which is not allowed. Set {nameof(SignatureVerificationParams.AllowAdhocSignatures)} to true is you want to check adhoc signatures.");
      return new VerifySignatureResult(VerifySignatureStatus.InvalidSignature);
    }

    SignedMessage signedMessage = null;

    bool skipSignedMessageVerification = section.SignatureType == MachOFile.SignatureType.AdHoc & signatureVerificationParams.AllowAdhocSignatures;

    if (!skipSignedMessageVerification)
    {
      signedMessage = SignedMessage.CreateInstance(section.SignatureData);
      var signatureVerificationResult = await _signedMessageVerifier.VerifySignatureAsync(signedMessage, signatureVerificationParams);

      if (!signatureVerificationResult.IsValid)
      {
        _logger?.Warning("Mach-O file signature verification failed: certificates or attributes validation failed");
        return signatureVerificationResult;
      }
    }

    if (!section.HashVerificationUnits.Any())
    {
      _logger?.Warning("Mach-O file signature verification failed: no hash verification units was found in the file");
      return new VerifySignatureResult(VerifySignatureStatus.InvalidFileHash);
    }

    // Verify hash slots (regular and special) in all Code Directories
    var codeDirectoryValidationResult = VerifyHashVerificationUnits(stream, section.HashVerificationUnits);

    if (!codeDirectoryValidationResult.IsValid)
    {
      _logger?.Warning("Mach-O file signature verification failed: at least one hash verification unit is invalid");
      return codeDirectoryValidationResult;
    }

    if (!section.CDHashes.Any())
    {
      _logger?.Warning("Mach-O file signature verification failed: no code directory hashes (CDHash) was found in the file");
      return new VerifySignatureResult(VerifySignatureStatus.InvalidFileHash);
    }

    if (section.CDHashes.Count() > 1 && !skipSignedMessageVerification)
    {
      var cdHashesVerificationResult = VerifyCDHashes(stream, section.CDHashes, signedMessage);

      if (!cdHashesVerificationResult.IsValid)
      {
        _logger?.Warning("Mach-O file signature verification failed: at leash one CDHash verification failed");
        return cdHashesVerificationResult;
      }
    }

    _logger?.Info("Mach-O file signature verification successfully passed");

    return VerifySignatureResult.Valid;
  }
}