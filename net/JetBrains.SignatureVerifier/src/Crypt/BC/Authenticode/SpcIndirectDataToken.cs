using System;
using System.Collections;
using Org.BouncyCastle.Cms;
using Org.BouncyCastle.Tsp;
using ContentInfo = Org.BouncyCastle.Asn1.Cms.ContentInfo;

namespace JetBrains.SignatureVerifier.Crypt.BC.Authenticode;

public class SpcIndirectDataToken
{
  private readonly CmsSignedData _signedData;

  private readonly SignerInformation _signerInfo;

  public SpcIndirectDataContent IndirectDataContent { get; }

  public SpcIndirectDataToken(
    ContentInfo contentInfo)
    : this(new CmsSignedData(contentInfo))
  {
  }

  public SpcIndirectDataToken(
    CmsSignedData signedData)
  {
    _signedData = signedData;

    if (!_signedData.SignedContentType.Equals(OIDs.SPC_INDIRECT_DATA))
    {
      throw new CmsException($"Invalid content type. Expected SPC_INDIRECT_DATA, got {signedData.SignedContentType}");
    }

    ICollection signers = _signedData.GetSignerInfos().GetSigners();

    if (signers.Count != 1)
      throw new ArgumentException($"SPC_INDIRECT_DATA token is signed by ${signers.Count} signers, but it must contain only 1 signature.");

    IEnumerator signerEnum = signers.GetEnumerator();

    signerEnum.MoveNext();
    _signerInfo = (SignerInformation)signerEnum.Current;

    try
    {
      Pkcs7ProcessableObject pkcs7ProcessableObject = _signedData.SignedContent as Pkcs7ProcessableObject;

      IndirectDataContent = SpcIndirectDataContent.GetInstance(pkcs7ProcessableObject.GetContent());
    }
    catch (CmsException e)
    {
      throw new TspException(e.Message, e.InnerException);
    }
  }
}