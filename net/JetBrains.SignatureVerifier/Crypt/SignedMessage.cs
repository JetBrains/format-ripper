using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using JetBrains.Annotations;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Cms;
using Org.BouncyCastle.Cms;
using Org.BouncyCastle.Pkix;
using Org.BouncyCastle.Utilities.Collections;
using Org.BouncyCastle.X509;
using Org.BouncyCastle.X509.Store;
using CmsSignedData = JetBrains.SignatureVerifier.BouncyCastle.Cms.CmsSignedData;
using SignerInformationStore = JetBrains.SignatureVerifier.BouncyCastle.Cms.SignerInformationStore;

namespace JetBrains.SignatureVerifier.Crypt
{
  public class SignedMessage
  {
    [CanBeNull] private readonly ILogger _logger;
    private readonly CmsSignedData _cmsSignedData;

    public SignedMessage([NotNull] byte[] pkcs7Data, [CanBeNull] ILogger logger)
    {
      _logger = logger ?? NullLogger.Instance;
      var _data = pkcs7Data ?? throw new ArgumentNullException(nameof(pkcs7Data));

      var asnStream = new Asn1InputStream(_data);
      var pkcs7 = ContentInfo.GetInstance(asnStream.ReadObject());
      _cmsSignedData = new CmsSignedData(pkcs7);
    }

    public SignedMessage([NotNull] byte[] signdeData, [NotNull] byte[] pkcs7Data, [CanBeNull] ILogger logger)
    {
      if (signdeData == null) throw new ArgumentNullException(nameof(signdeData));
      if (pkcs7Data == null) throw new ArgumentNullException(nameof(pkcs7Data));

      _logger = logger ?? NullLogger.Instance;
      var signedContent = new CmsProcessableByteArray(signdeData);

      try
      {
        using var asnStream = new Asn1InputStream(pkcs7Data);
        var pkcs7 = ContentInfo.GetInstance(asnStream.ReadObject());
        _cmsSignedData = new CmsSignedData(signedContent, pkcs7);
      }
      catch (IOException ex)
      {
        _logger.Error($"Invalid signature format. {ex.FlatMessages()}");
        throw;
      }
    }

    internal SignedMessage([NotNull] Asn1Object obj, [CanBeNull] ILogger logger)
    {
      if (obj == null) throw new ArgumentNullException(nameof(obj));
      _logger = logger ?? NullLogger.Instance;
      var pkcs7 = ContentInfo.GetInstance(obj);
      _cmsSignedData = new CmsSignedData(pkcs7);
    }

    public Task<VerifySignatureResult> VerifySignatureAsync(
      [NotNull] SignatureVerificationParams signatureVerificationParams)
    {
      if (signatureVerificationParams == null)
        throw new ArgumentNullException(nameof(signatureVerificationParams));

      _logger.Trace($"Verify with params: {signatureVerificationParams}");

      return verifySignatureAsync(_cmsSignedData, signatureVerificationParams);
    }

    private Task<VerifySignatureResult> verifySignatureAsync(CmsSignedData cmsSignedData,
      SignatureVerificationParams signatureVerificationParams)
    {
      var certs = cmsSignedData.GetCertificates("Collection");
      var signersStore = cmsSignedData.GetSignerInfos();
      return verifySignatureAsync(signersStore, certs, signatureVerificationParams);
    }

    private async Task<VerifySignatureResult> verifySignatureAsync(
      SignerInformationStore signersStore,
      IX509Store certs,
      SignatureVerificationParams signatureVerificationParams)
    {
      foreach (JetBrains.SignatureVerifier.BouncyCastle.Cms.SignerInformation signer in signersStore.GetSigners())
      {
        var siv = new SignerInfoVerifier(signer, certs, _logger);
        var result = await siv.VerifyAsync(signatureVerificationParams);

        if (result != VerifySignatureResult.Valid)
          return result;
      }

      return VerifySignatureResult.Valid;
    }
  }
}