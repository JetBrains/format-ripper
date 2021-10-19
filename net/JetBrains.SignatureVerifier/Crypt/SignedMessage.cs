using System;
using System.IO;
using JetBrains.Annotations;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Cms;
using Org.BouncyCastle.Cms;
using CmsSignedData = JetBrains.SignatureVerifier.BouncyCastle.Cms.CmsSignedData;

namespace JetBrains.SignatureVerifier.Crypt
{
  public class SignedMessage
  {
    private readonly CmsSignedData _cmsSignedData;

    public CmsSignedData SignedData => _cmsSignedData;


    public static SignedMessage CreateInstance(SignatureData signatureData)
    {
      if (signatureData.IsEmpty)
        throw new InvalidDataException(nameof(signatureData));

      if (signatureData.HasAttachedSignedData)
        return new SignedMessage(signatureData.SignedData, signatureData.CmsData);
      return new SignedMessage(signatureData.CmsData);
    }

    public SignedMessage([NotNull] byte[] pkcs7Data)
    {
      if (pkcs7Data == null) throw new ArgumentNullException(nameof(pkcs7Data));
      var _data = pkcs7Data ?? throw new ArgumentNullException(nameof(pkcs7Data));

      var asnStream = new Asn1InputStream(_data);
      var pkcs7 = ContentInfo.GetInstance(asnStream.ReadObject());
      _cmsSignedData = new CmsSignedData(pkcs7);
    }

    public SignedMessage([NotNull] byte[] signedData, [NotNull] byte[] pkcs7Data)
    {
      if (signedData == null) throw new ArgumentNullException(nameof(signedData));
      if (pkcs7Data == null) throw new ArgumentNullException(nameof(pkcs7Data));
      var signedContent = new CmsProcessableByteArray(signedData);

      try
      {
        using var asnStream = new Asn1InputStream(pkcs7Data);
        var pkcs7 = ContentInfo.GetInstance(asnStream.ReadObject());
        _cmsSignedData = new CmsSignedData(signedContent, pkcs7);
      }
      catch (IOException ex)
      {
        throw new Exception("Invalid signature format", ex);
      }
    }

    internal SignedMessage([NotNull] Asn1Object obj)
    {
      if (obj == null) throw new ArgumentNullException(nameof(obj));
      var pkcs7 = ContentInfo.GetInstance(obj);
      _cmsSignedData = new CmsSignedData(pkcs7);
    }
  }
}