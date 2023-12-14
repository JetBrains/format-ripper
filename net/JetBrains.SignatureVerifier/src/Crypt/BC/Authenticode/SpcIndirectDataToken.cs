using System;
using System.Collections;
using Org.BouncyCastle.Cms;
using Org.BouncyCastle.Tsp;
using ContentInfo = Org.BouncyCastle.Asn1.Cms.ContentInfo;

namespace JetBrains.SignatureVerifier.Crypt.BC.Authenticode;

/// <summary>
/// Class that represents Microsoft Authenticode structure SpcIndirectDataToken
/// </summary>
public class SpcIndirectDataToken
{
  public SignerInformation SignerInfo { get; }

  public SpcIndirectDataContent IndirectDataContent { get; }

  public SpcIndirectDataToken(
    CmsSignedData signedData)
  {
    if (signedData.SignedContent == null)
      throw new ArgumentException("SignedContent is empty");

    if (!signedData.SignedContentType.Equals(OIDs.SPC_INDIRECT_DATA))
      throw new CmsException($"Invalid content type. Expected SPC_INDIRECT_DATA, got {signedData.SignedContentType}");

    ICollection signers = signedData.GetSignerInfos().GetSigners();

    if (signers.Count != 1)
      throw new AuthenticodeException($"SPC_INDIRECT_DATA token is signed by ${signers.Count} signers, but it must contain only 1 signature.");

    IEnumerator signerEnum = signers.GetEnumerator();

    signerEnum.MoveNext();
    SignerInfo = (SignerInformation)signerEnum.Current;

    Pkcs7ProcessableObject pkcs7ProcessableObject = signedData.SignedContent as Pkcs7ProcessableObject;

    if (pkcs7ProcessableObject == null)
      throw new AuthenticodeException($"Invalid type of SignedContent: ${signedData.SignedContent.GetType()}");

    try
    {
      IndirectDataContent = SpcIndirectDataContent.GetInstance(pkcs7ProcessableObject.GetContent());
    }
    catch (Exception e)
    {
      throw new AuthenticodeException(e.Message, e.InnerException);
    }
  }
}