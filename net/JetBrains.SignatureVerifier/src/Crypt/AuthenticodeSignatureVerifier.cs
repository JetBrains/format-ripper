using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using JetBrains.Annotations;
using JetBrains.FormatRipper;
using JetBrains.FormatRipper.Compound;
using JetBrains.FormatRipper.Pe;
using JetBrains.SignatureVerifier.Crypt.BC;
using JetBrains.SignatureVerifier.Crypt.BC.Authenticode;
using Org.BouncyCastle.Asn1.Cms;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;
using Attribute = Org.BouncyCastle.Asn1.Cms.Attribute;

namespace JetBrains.SignatureVerifier.Crypt;

/// <summary>
/// Class for file hash validation
/// </summary>
public class AuthenticodeSignatureVerifier
{
  private readonly ILogger _logger;
  private readonly SignedMessageVerifier _signedMessageVerifier;

  /// <summary>
  /// Constructs new verifier
  /// </summary>
  /// <param name="logger">Logger</param>
  public AuthenticodeSignatureVerifier([CanBeNull] ILogger logger) : this(new SignedMessageVerifier(logger), logger)
  {
  }

  /// <summary>
  /// Constructs new verifier
  /// </summary>
  /// <param name="signedMessageVerifier">Signed message verifier</param>
  /// <param name="logger">Logger</param>
  public AuthenticodeSignatureVerifier([NotNull] SignedMessageVerifier signedMessageVerifier, [CanBeNull] ILogger logger)
  {
    _signedMessageVerifier = signedMessageVerifier ?? throw new ArgumentNullException(nameof(signedMessageVerifier));
    _logger = logger ?? NullLogger.Instance;
  }

  /// <summary>
  /// Verify PE file signature and file integrity
  /// </summary>
  /// <param name="peFile">Parsed PE file</param>
  /// <param name="stream">File stream</param>
  /// <param name="signatureVerificationParams">Signature verification params</param>
  /// <param name="fileIntegrityVerificationParams">File integrity verification params</param>
  /// <returns>Verification result</returns>
  /// <exception cref="ArgumentException"></exception>
  public async Task<VerifySignatureResult> VerifyAsync(
    PeFile peFile,
    Stream stream,
    SignatureVerificationParams signatureVerificationParams,
    FileIntegrityVerificationParams fileIntegrityVerificationParams)
  {
    if (peFile.ComputeHashInfo == null) throw new ArgumentException($"PE file was parsed without {nameof(PeFile.Mode.ComputeHashInfo)} flag", nameof(peFile));

    return await VerifyAsync(peFile.SignatureData, peFile.ComputeHashInfo, stream, signatureVerificationParams, fileIntegrityVerificationParams);
  }

  /// <summary>
  /// Verify MSI file signature and file integrity
  /// </summary>
  /// <param name="msiFile">Parsed Compound file</param>
  /// <param name="stream">File stream</param>
  /// <param name="signatureVerificationParams">Signature verification params</param>
  /// <param name="fileIntegrityVerificationParams">File integrity verification params</param>
  /// <returns>Verification result</returns>
  /// <exception cref="ArgumentException"></exception>
  public async Task<VerifySignatureResult> VerifyAsync(
    CompoundFile msiFile,
    Stream stream,
    SignatureVerificationParams signatureVerificationParams,
    FileIntegrityVerificationParams fileIntegrityVerificationParams)
  {
    if (msiFile.ComputeHashInfo == null) throw new ArgumentException($"Compound file was parsed without {nameof(CompoundFile.Mode.ComputeHashInfo)} flag", nameof(msiFile));

    return await VerifyAsync(msiFile.SignatureData, msiFile.ComputeHashInfo, stream, signatureVerificationParams, fileIntegrityVerificationParams);
  }

  /// <summary>
  /// Calculate file's hash and compare it with value from signature
  /// </summary>
  /// <param name="signatureData">Signature data</param>
  /// <param name="computeHashInfo">Hash computation information</param>
  /// <param name="stream">File stream</param>
  /// <param name="signatureVerificationParams">Signature verification params</param>
  /// <param name="fileIntegrityVerificationParams">File integrity verification parameters</param>
  /// <returns>Validation result.
  /// Returns FileIntegrityDataNotFound if the signature token with the expected hash value was not found.</returns>
  public async Task<VerifySignatureResult> VerifyAsync(
    SignatureData signatureData,
    [NotNull] ComputeHashInfo computeHashInfo,
    [NotNull] Stream stream,
    [NotNull] SignatureVerificationParams signatureVerificationParams,
    [NotNull] FileIntegrityVerificationParams fileIntegrityVerificationParams)
  {
    if (computeHashInfo == null) throw new ArgumentNullException(nameof(computeHashInfo));
    if (stream == null) throw new ArgumentNullException(nameof(stream));
    if (signatureVerificationParams == null) throw new ArgumentNullException(nameof(signatureVerificationParams));
    if (fileIntegrityVerificationParams == null) throw new ArgumentNullException(nameof(fileIntegrityVerificationParams));

    var signedMessage = SignedMessage.CreateInstance(signatureData);
    var signatureVerificationResult = await _signedMessageVerifier.VerifySignatureAsync(signedMessage, signatureVerificationParams);

    if (!signatureVerificationResult.IsValid)
    {
      _logger?.Warning("Authenticode signature verification failed: certificates or attributes validation failed");
      return signatureVerificationResult;
    }

    var fileIntegrityVerificationResult = VerifyFileIntegrity(signedMessage, computeHashInfo, stream, fileIntegrityVerificationParams);

    if (!fileIntegrityVerificationResult.IsValid)
      _logger?.Warning("Authenticode signature verification failed: file integrity verification failed");
    else
      _logger?.Info("Authenticode signature verification successfully passed");

    return fileIntegrityVerificationResult;
  }

  /// <summary>
  /// Compute file hash and compare it against values from SignedContent and Counter signatures
  /// </summary>
  /// <param name="signedMessage">Signed message</param>
  /// <param name="computeHashInfo">Hash computation info</param>
  /// <param name="stream">File stream</param>
  /// <param name="fileIntegrityVerificationParams">File integrity verification params</param>
  /// <returns>File integrity verification result</returns>
  /// <exception cref="ArgumentNullException"></exception>
  private VerifySignatureResult VerifyFileIntegrity(
    [NotNull] SignedMessage signedMessage,
    [NotNull] ComputeHashInfo computeHashInfo,
    [NotNull] Stream stream,
    [NotNull] FileIntegrityVerificationParams fileIntegrityVerificationParams)
  {
    if (signedMessage == null) throw new ArgumentNullException(nameof(signedMessage));
    if (computeHashInfo == null) throw new ArgumentNullException(nameof(computeHashInfo));
    if (stream == null) throw new ArgumentNullException(nameof(stream));
    if (fileIntegrityVerificationParams == null) throw new ArgumentNullException(nameof(fileIntegrityVerificationParams));

    var signedDataTokens = GetIndirectDataTokens(signedMessage);

    bool hasValidSignatures = false;
    bool hasInvalidSignatures = false;

    var algorithms = signedDataTokens
      .Select(t => t.IndirectDataContent.DigestInfo.AlgorithmID);

    IDictionary<AlgorithmIdentifier, byte[]> hashes = HashUtil.ComputeHashes(stream, computeHashInfo, algorithms);

    foreach (var spcIndirectDataToken in signedDataTokens)
    {
      AlgorithmIdentifier algId = spcIndirectDataToken.IndirectDataContent.DigestInfo.AlgorithmID;

      var imageHash = hashes[algId];

      byte[] expectedHash = spcIndirectDataToken.IndirectDataContent.DigestInfo.GetDigest();

      if (imageHash.Length == expectedHash.Length && Arrays.FixedTimeEquals(imageHash, expectedHash))
      {
        hasValidSignatures = true;
      }
      else
      {
        hasInvalidSignatures = true;
        var algName = DigestUtilities.GetAlgorithmName(algId.Algorithm);
        if (!fileIntegrityVerificationParams.AllowHashMismatches)
        {
          _logger?.Warning($"Authenticode signature verification error: hash value mismatch for the algorithm {algName}");
          break;
        }

        _logger?.Warning($"Authenticode signature verification warning: hash value mismatch for the algorithm {algName}");
      }
    }

    VerifySignatureResult fileIntegrityVerificationResult = (hasValidSignatures, hasInvalidSignatures, fileIntegrityVerificationParams.AllowHashMismatches) switch
    {
      (false, false, _) => new VerifySignatureResult(VerifySignatureStatus.FileIntegrityDataNotFound),
      (true, _, true) => VerifySignatureResult.Valid,
      (true, false, _) => VerifySignatureResult.Valid,
      _ => new VerifySignatureResult(VerifySignatureStatus.InvalidFileHash),
    };
    return fileIntegrityVerificationResult;
  }

  /// <summary>
  /// Extract SPC_INDIRECT_DATA tokens from SignedData's content and from nested signatures
  /// stored in unsigned attributes collection.
  /// </summary>
  /// <returns>List of SPC_INDIRECT_DATA tokens</returns>
  private IEnumerable<SpcIndirectDataToken> GetIndirectDataTokens(SignedMessage signedMessage)
  {
    List<SpcIndirectDataToken> tokens = new List<SpcIndirectDataToken>();

    if (signedMessage.SignedData.SignedContent != null && signedMessage.SignedData.SignedContentType.Equals(OIDs.SPC_INDIRECT_DATA))
    {
      tokens.Add(new SpcIndirectDataToken(signedMessage.SignedData));
    }

    var signersStore = signedMessage.SignedData.GetSignerInfos();

    foreach (SignerInformation signer in signersStore.GetSigners())
    {
      if (signer.UnsignedAttributes != null)
      {
        var nestedSignatures = signer.UnsignedAttributes.GetAll(OIDs.SPC_NESTED_SIGNATURE);

        foreach (Attribute nestedSignature in nestedSignatures)
        {
          foreach (var nestedSignatureAttrValue in nestedSignature.AttrValues)
          {
            var contentInfo = ContentInfo.GetInstance(nestedSignatureAttrValue);
            var cmsSignedData = new CmsSignedData(contentInfo);

            if (cmsSignedData.SignedContent != null && cmsSignedData.SignedContentType.Equals(OIDs.SPC_INDIRECT_DATA))
            {
              tokens.Add(new SpcIndirectDataToken(cmsSignedData));
            }
          }
        }
      }
    }

    return tokens;
  }
}