using Newtonsoft.Json;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Cms;
using Org.BouncyCastle.Asn1.X509;

namespace JetBrains.Serialization;

[JsonObject(MemberSerialization.Fields)]
public class RSASignedDataInfo : IEncodableInfo
{
  public TextualInfo Identifier { get; }
  public bool Explicit { get; }
  public int TagNo { get; }
  public TextualInfo Version { get; }
  public List<AlgorithmInfo> DigestAlgorithmsInfo { get; }
  public EncapContentInfo EncapContentInfo { get; }
  public TaggedObjectInfo Certificates { get; }
  public List<CounterSignatureInfo> CounterSignatureInfos { get; }

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
    Identifier = identifier;
    Explicit = isExplicit;
    TagNo = tagNo;
    Version = version;
    DigestAlgorithmsInfo = digestAlgorithmsInfo;
    EncapContentInfo = encapContentInfo;
    Certificates = certificates;
    CounterSignatureInfos = counterSignatureInfos;
  }

  public static RSASignedDataInfo GetInstance(Asn1Sequence originalSequence)
  {
    var identifier = TextualInfo.GetInstance(originalSequence[0]);

    var tagged = originalSequence[1] as DerTaggedObject;
    int tagNo = tagged.TagNo;

    var sequence = tagged.GetObject() as DerSequence;

    var iterator = sequence.GetEnumerator();
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
      Identifier.ToPrimitive(),
      TaggedObjectInfo.GetTaggedObject(
        Explicit,
        TagNo,
        new List<Asn1Encodable?>
        {
          Version.ToPrimitive(),
          DigestAlgorithmsInfo.ToPrimitiveDerSet(),
          EncapContentInfo.ToPrimitive(),
          Certificates.ToPrimitive(),
          CounterSignatureInfos.ToPrimitiveDerSet()
        }.ToDerSequence()
      )
    }
    .ToDerSequence();
}