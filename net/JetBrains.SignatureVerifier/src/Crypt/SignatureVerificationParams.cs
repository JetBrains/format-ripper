using System;
using System.IO;
using System.Linq;
using Org.BouncyCastle.Pkix;
using Org.BouncyCastle.Utilities.Collections;
using Org.BouncyCastle.X509;

namespace JetBrains.SignatureVerifier.Crypt
{
  public class SignatureVerificationParams
  {
    private readonly Stream _signRootCertStore;
    private readonly Stream _timestampRootCertStore;

    public bool BuildChain { get; private set; }
    public bool WithRevocationCheck { get; private set; }
    public TimeSpan OcspResponseTimeout { get; private set; }
    public SignatureValidationTimeMode SignValidationTimeMode { get; private set; }
    public DateTime? SignatureValidationTime { get; private set; }

    private string SignatureValidationTimeFormatted =>
      SignatureValidationTime.HasValue ? SignatureValidationTime.ToString() : "<null>";

    private HashSet _rootCertificates;
    internal HashSet RootCertificates => _rootCertificates ??= readRootCertificates();

    /// <summary>
    /// Initialize SignatureVerificationParams
    /// </summary>
    /// <param name="signRootCertStore">Stream of PKCS #7 store with CA certificates for which a chain will be build and validate</param>
    /// <param name="timestampRootCertStore">Stream of PKCS #7 store with a timestamp CA certificates for which a chain will be build and validate</param>
    /// <param name="buildChain">If true - build and verify a certificates chain (by default true)</param>
    /// <param name="withRevocationCheck">If true - verify a revocation status for certificates in all chains (apply if buildChain is true, by default true)</param>
    /// <param name="ocspResponseTimeout">Timeout for OCSP request (5 sec. by default) (apply if withRevocationCheck is true)</param>
    /// <param name="signatureValidationTimeMode">Mode of selection time which is used for certificates and CRLs validation (SignatureValidationTimeMode.Timestamp by default)</param>
    /// <param name="signatureValidationTime">Time which is used when signatureValidationTimeMode is SignValidationTime</param>
    public SignatureVerificationParams(
      Stream signRootCertStore = null,
      Stream timestampRootCertStore = null,
      bool buildChain = true,
      bool withRevocationCheck = true,
      TimeSpan? ocspResponseTimeout = null,
      SignatureValidationTimeMode signatureValidationTimeMode = SignatureValidationTimeMode.Timestamp,
      DateTime? signatureValidationTime = null)
    {
      _signRootCertStore = signRootCertStore;
      _timestampRootCertStore = timestampRootCertStore;
      BuildChain = buildChain;
      WithRevocationCheck = withRevocationCheck;
      OcspResponseTimeout = ocspResponseTimeout ?? TimeSpan.FromSeconds(5);
      SignValidationTimeMode = signatureValidationTimeMode;

      if (SignValidationTimeMode == SignatureValidationTimeMode.SignValidationTime
          && signatureValidationTime is null)
        throw new ArgumentNullException(nameof(signatureValidationTime));

      SignatureValidationTime = signatureValidationTime;
    }

    public void SetSignValidationTime(DateTime signValidationTime)
    {
      if (SignValidationTimeMode != SignatureValidationTimeMode.Timestamp)
        throw new InvalidOperationException("Invalid SignValidationTimeMode");

      if (SignatureValidationTime.HasValue)
        throw new InvalidOperationException("SignatureValidationTime already set");

      SignatureValidationTime = signValidationTime;
    }

    private HashSet readRootCertificates()
    {
      if (_signRootCertStore is null
          && _timestampRootCertStore is null)
        return null;

      HashSet rootCerts = new HashSet();
      X509CertificateParser parser = new X509CertificateParser();
      addCerts(_signRootCertStore);
      addCerts(_timestampRootCertStore);
      return rootCerts;

      void addCerts(Stream storeStream)
      {
        if (storeStream is not null)
        {
          storeStream.Position = 0;
          rootCerts.AddAll(parser.ReadCertificates(storeStream)
            .Cast<X509Certificate>()
            .Select(cert => new TrustAnchor(cert, new byte[0])));
        }
      }
    }

    public override string ToString()
    {
      return
        $"{nameof(BuildChain)}: {BuildChain}, {nameof(WithRevocationCheck)}: {WithRevocationCheck}, {nameof(OcspResponseTimeout)}: {OcspResponseTimeout}, {nameof(SignValidationTimeMode)}: {SignValidationTimeMode}, {nameof(SignatureValidationTime)}: {SignatureValidationTimeFormatted}";
    }
  }

  public enum SignatureValidationTimeMode
  {
    /// <summary>
    /// Extract a timestamp or signing time (1.2.840.113549.1.9.5) from a signed message
    /// </summary>
    Timestamp,

    /// <summary>
    /// Validate signatures in the current time
    /// </summary>
    Current,

    /// <summary>
    /// Validate signatures in the particular time
    /// </summary>
    SignValidationTime
  }
}