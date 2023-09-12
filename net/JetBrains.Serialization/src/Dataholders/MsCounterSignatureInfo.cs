using Newtonsoft.Json;
using Org.BouncyCastle.Asn1;
using JetBrains.Serialization;
using Org.BouncyCastle.Asn1.X509;

[JsonObject(MemberSerialization.OptIn)]
public class MsCounterSignatureInfo : IEncodableInfo
{
  [JsonProperty("Version")] private int _version;
  [JsonProperty("Algorithms")] private List<AlgorithmInfo> _algorithms;
  [JsonProperty("TstInfo")] private TSTInfo _tstInfo;

  [JsonProperty("TaggedCertificateInfo")]
  private TaggedObjectInfo _taggedCertificateInfo;

  [JsonProperty("CounterSignatures")] private List<CounterSignatureInfo> _counterSignatures;

  [JsonConstructor]
  public MsCounterSignatureInfo(
    int version,
    List<AlgorithmInfo> algorithms,
    TSTInfo tstInfo,
    TaggedObjectInfo taggedCertificateInfo,
    List<CounterSignatureInfo> counterSignatures)
  {
    _version = version;
    _algorithms = algorithms;
    _tstInfo = tstInfo;
    _taggedCertificateInfo = taggedCertificateInfo;
    _counterSignatures = counterSignatures;
  }

  public static MsCounterSignatureInfo GetInstance(DerSequence sequence)
  {
    var enumerator = sequence.GetEnumerator();

    enumerator.MoveNext();
    var version = ((DerInteger)enumerator.Current).Value.IntValue;

    enumerator.MoveNext();
    var algorithms = ((DerSet)enumerator.Current)
      .OfType<DerSequence>()
      .ToList()
      .Select(derSequence => new AlgorithmInfo(AlgorithmIdentifier.GetInstance(derSequence)))
      .ToList();

    enumerator.MoveNext();
    var tstInfo = new TSTInfo((DerSequence)enumerator.Current);

    enumerator.MoveNext();

    TaggedObjectInfo certificateInfoTagged = new TaggedObjectInfo(
      ((DerTaggedObject)enumerator.Current).IsExplicit(),
      ((DerTaggedObject)enumerator.Current).TagNo,
      new SequenceInfo(
        ((DerSequence)((DerTaggedObject)enumerator.Current).GetObject()).ToArray()
        .Select(it => CertificateInfo.GetInstance(it.ToAsn1Object())).ToList()
      )
    );

    enumerator.MoveNext();
    var counterSignatures = ((DerSet)enumerator.Current)
      .OfType<DerSequence>()
      .Select(CounterSignatureInfo.GetInstance)
      .ToList();

    return new MsCounterSignatureInfo(
      version,
      algorithms,
      tstInfo,
      certificateInfoTagged,
      counterSignatures);
  }

  public virtual Asn1Encodable ToPrimitive() =>
    new List<Asn1Encodable>
    {
      new DerInteger(_version),
      _algorithms.ToPrimitiveDerSet(),
      _tstInfo.ToPrimitive(),
      _taggedCertificateInfo.ToPrimitive(),
      _counterSignatures.ToPrimitiveDerSet()
    }.ToDerSequence();
}