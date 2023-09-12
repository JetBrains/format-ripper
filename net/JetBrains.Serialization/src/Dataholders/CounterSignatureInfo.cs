using Newtonsoft.Json;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using Attribute = Org.BouncyCastle.Asn1.Cms.Attribute;

namespace JetBrains.Serialization;

[JsonObject(MemberSerialization.OptIn)]
public class CounterSignatureInfo : IEncodableInfo
{
  [JsonProperty("Version")] private int _version;
  [JsonProperty("Sid")] private SignerIdentifierInfo _sid;
  [JsonProperty("DigestAlgorithm")] private AlgorithmInfo _digestAlgorithm;

  [JsonProperty("AuthenticatedAttributes")]
  private List<AttributeInfo> _authenticatedAttributes;

  [JsonProperty("DigestEncryptionAlgorithm")]
  private AlgorithmInfo _digestEncryptionAlgorithm;

  [JsonProperty("EncryptedDigest")] private TextualInfo _encryptedDigest;
  [JsonProperty("CounterSignature")] private TaggedObjectInfo? _counterSignature;

  [JsonConstructor]
  public CounterSignatureInfo(
    int version,
    SignerIdentifierInfo sid,
    AlgorithmInfo digestAlgorithm,
    List<AttributeInfo> authenticatedAttributes,
    AlgorithmInfo digestEncryptionAlgorithm,
    TextualInfo encryptedDigest,
    TaggedObjectInfo? counterSignature = null)
  {
    _version = version;
    _sid = sid;
    _digestAlgorithm = digestAlgorithm;
    _authenticatedAttributes = authenticatedAttributes;
    _digestEncryptionAlgorithm = digestEncryptionAlgorithm;
    _encryptedDigest = encryptedDigest;
    _counterSignature = counterSignature;
  }

  public static CounterSignatureInfo GetInstance(DerSequence sequence)
  {
    var iterator = sequence.GetEnumerator();
    iterator.MoveNext();

    var version = ((DerInteger)iterator.Current).Value.IntValue;
    iterator.MoveNext();

    var signerSequence = ((DerSequence)iterator.Current).ToArray();

    var signerIdentifierInfo = new SignerIdentifierInfo(
      X509Name.GetInstance(signerSequence[0]),
      (DerInteger)signerSequence[1]
    );
    iterator.MoveNext();

    var digestAlgorithm = new AlgorithmInfo(AlgorithmIdentifier.GetInstance(iterator.Current));
    iterator.MoveNext();

    var attributes = ((DerSequence)((DerTaggedObject)iterator.Current).GetObject())
      .ToArray()
      .Select(it => AttributeInfo.GetInstance(Attribute.GetInstance(it)))
      .ToList();
    iterator.MoveNext();

    var encryptionAlgorithm = new AlgorithmInfo(AlgorithmIdentifier.GetInstance(iterator.Current));
    iterator.MoveNext();

    var encryptedDigest = TextualInfo.GetInstance((Asn1Encodable)iterator.Current);

    TaggedObjectInfo? counterSignature = null;
    if (iterator.MoveNext())
    {
      var obj = (DerTaggedObject)iterator.Current;
      counterSignature = new TaggedObjectInfo(
        obj.IsExplicit(),
        obj.TagNo,
        AttributeInfo.GetInstance(Attribute.GetInstance(obj.GetObject())));
    }

    return new CounterSignatureInfo(
      version,
      signerIdentifierInfo,
      digestAlgorithm,
      attributes,
      encryptionAlgorithm,
      encryptedDigest,
      counterSignature);
  }

  public Asn1Encodable ToPrimitive()
  {
    var primitiveValues = new List<Asn1Encodable>
    {
      new DerInteger(_version),
      _sid.ToPrimitive(),
      _digestAlgorithm.ToPrimitive(),
      TaggedObjectInfo.GetTaggedObject(false, 0, _authenticatedAttributes.ToPrimitiveDerSet()),
      _digestEncryptionAlgorithm.ToPrimitive(),
      _encryptedDigest.ToPrimitive()
    };

    if (_counterSignature != null)
    {
      primitiveValues.Add(_counterSignature.ToPrimitive());
    }

    return primitiveValues.ToDerSequence();
  }
}