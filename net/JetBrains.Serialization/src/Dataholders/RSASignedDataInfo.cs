using Newtonsoft.Json;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Cms;
using Org.BouncyCastle.Asn1.X509;

namespace JetBrains.Serialization;

[JsonObject(MemberSerialization.Fields)]
public class RSASignedDataInfo : IEncodableInfo
{
  [JsonProperty("Identifier")] private TextualInfo _identifier;
  [JsonProperty("Explicit")] private bool _explicit;
  [JsonProperty("TagNo")] private int _tagNo;
  [JsonProperty("Version")] private TextualInfo _version;
  [JsonProperty("DigestAlgorithmsInfo")] private List<AlgorithmInfo> _digestAlgorithmsInfo;
  [JsonProperty("EncapContentInfo")] private EncapContentInfo _encapContentInfo;
  [JsonProperty("Certificates")] private TaggedObjectInfo _certificates;

  [JsonProperty("CounterSignatureInfos")]
  private List<CounterSignatureInfo> _counterSignatureInfos;

  [JsonConstructor]
  public RSASignedDataInfo(
    TextualInfo identifier,
    bool isExplicit,
    int tagNo,
    TextualInfo version,
    List<AlgorithmInfo> digestAlgorithmsInfo,
    EncapContentInfo encapContentInfo,
    TaggedObjectInfo certificates,
    List<CounterSignatureInfo> counterSignatureInfos)
  {
    _identifier = identifier;
    _explicit = isExplicit;
    _tagNo = tagNo;
    _version = version;
    _digestAlgorithmsInfo = digestAlgorithmsInfo;
    _encapContentInfo = encapContentInfo;
    _certificates = certificates;
    _counterSignatureInfos = counterSignatureInfos;
  }

  public static RSASignedDataInfo GetInstance(Asn1Sequence originalSequence)
  {
    var identifier = TextualInfo.GetInstance(originalSequence[0]);

    var tagged = originalSequence[1] as DerTaggedObject;
    int tagNo = tagged!.TagNo;

    var sequence = tagged.GetObject() as DerSequence;

    var iterator = sequence!.GetEnumerator();
    iterator.MoveNext();

    var version = TextualInfo.GetInstance((Asn1Encodable)iterator.Current!);
    iterator.MoveNext();

    var algorithms = ((DerSet)iterator.Current!)
      .ToArray()
      .Select(it => new AlgorithmInfo(AlgorithmIdentifier.GetInstance(it))).ToList();
    iterator.MoveNext();

    var encapContentInfo = EncapContentInfo.GetInstance(ContentInfo.GetInstance(iterator.Current));
    iterator.MoveNext();

    var certificateObject = (DerTaggedObject)iterator.Current;
    var certificates = new TaggedObjectInfo(
      certificateObject.IsExplicit(),
      certificateObject.TagNo,
      new SequenceInfo(((DerSequence)certificateObject.GetObject()).ToArray()
        .Select(it => CertificateInfo.GetInstance(it.ToAsn1Object())).ToList())
    );
    iterator.MoveNext();

    var counterSignaturesSet = (DerSet)iterator.Current;

    var counterSignatures =
      counterSignaturesSet.ToArray()
        .Select(it => CounterSignatureInfo.GetInstance((DerSequence)it)).ToList();


    return new RSASignedDataInfo(
      identifier,
      tagged.IsExplicit(),
      tagNo,
      version,
      algorithms,
      encapContentInfo,
      certificates,
      counterSignatures
    );
  }

  public Asn1Encodable ToPrimitive() => new List<Asn1Encodable?>
    {
      _identifier.ToPrimitive(),
      TaggedObjectInfo.GetTaggedObject(
        _explicit,
        _tagNo,
        new List<Asn1Encodable?>
        {
          _version.ToPrimitive(),
          _digestAlgorithmsInfo.ToPrimitiveDerSet(),
          _encapContentInfo.ToPrimitive(),
          _certificates.ToPrimitive(),
          _counterSignatureInfos.ToPrimitiveDerSet()
        }.ToDerSequence()
      )
    }
    .ToDerSequence();
}