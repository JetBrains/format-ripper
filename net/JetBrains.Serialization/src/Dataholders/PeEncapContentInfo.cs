using Newtonsoft.Json;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Cms;
using Org.BouncyCastle.Asn1.X509;

namespace JetBrains.Serialization;

[JsonObject(MemberSerialization.Fields)]
public class PeEncapContentInfo : EncapContentInfo
{
  protected override TextualInfo ContentType { get; }
  public ImageDataObjIdInfo ImageDataObjIdInfo { get; }
  public AlgorithmInfo HashAlgorithmInfo { get; }
  public TextualInfo ContentHash { get; }

  public PeEncapContentInfo(TextualInfo contentType, ImageDataObjIdInfo imageDataObjIdInfo,
    AlgorithmInfo hashAlgorithmInfo, TextualInfo contentHash)
  {
    ContentType = contentType;
    ImageDataObjIdInfo = imageDataObjIdInfo;
    HashAlgorithmInfo = hashAlgorithmInfo;
    ContentHash = contentHash;
  }

  public static PeEncapContentInfo GetInstance(ContentInfo contentInfo)
  {
    var contentSequence = ((DerSequence)contentInfo.Content).ToArray();
    var algorithmSequence = ((DerSequence)contentSequence[1]).ToArray();

    return new PeEncapContentInfo(
      TextualInfo.GetInstance(contentInfo.ContentType),
      ImageDataObjIdInfo.GetInstance((DerSequence)contentSequence.First()),
      new AlgorithmInfo((AlgorithmIdentifier.GetInstance(algorithmSequence.First()))),
      TextualInfo.GetInstance(algorithmSequence[1]));
  }

  protected override Asn1Encodable GetContentPrimitive()
    =>
      new List<Asn1Encodable?>
      {
        ImageDataObjIdInfo.ToPrimitive(),
        new List<IEncodableInfo>
        {
          HashAlgorithmInfo,
          ContentHash
        }.ToPrimitiveDerSequence()
      }.ToDerSequence();
}