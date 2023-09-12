using Newtonsoft.Json;
using Org.BouncyCastle.Asn1;
using JetBrains.Serialization;
using SignerInformation = JetBrains.SignatureVerifier.Crypt.BC.SignerInformation;

[JsonObject(MemberSerialization.OptIn)]
public class SignerInfo : IEncodableInfo
{
  [JsonProperty("Version")] private int _version;
  [JsonProperty("Sid")] private SignerIdentifierInfo _sid;
  [JsonProperty("DigestAlgorithm")] private AlgorithmInfo _digestAlgorithm;

  [JsonProperty("AuthenticatedAttributes")]
  private List<AttributeInfo> _authenticatedAttributes;

  [JsonProperty("DigestEncryptionAlgorithm")]
  private AlgorithmInfo _digestEncryptionAlgorithm;

  [JsonProperty("EncryptedDigest")] private TextualInfo _encryptedDigest;

  [JsonProperty("UnauthenticatedAttributes")]
  private List<AttributeInfo>? _unauthenticatedAttributes;

  [JsonConstructor]
  public SignerInfo(int version, SignerIdentifierInfo sid, AlgorithmInfo digestAlgorithm,
    List<AttributeInfo> authenticatedAttributes, AlgorithmInfo digestEncryptionAlgorithm, TextualInfo encryptedDigest,
    List<AttributeInfo>? unauthenticatedAttributes)
  {
    _version = version;
    _sid = sid;
    _digestAlgorithm = digestAlgorithm;
    _authenticatedAttributes = authenticatedAttributes;
    _digestEncryptionAlgorithm = digestEncryptionAlgorithm;
    _encryptedDigest = encryptedDigest;
    _unauthenticatedAttributes = unauthenticatedAttributes;
  }


  public SignerInfo(SignerInformation signer)
  {
    _version = signer.Version;
    _sid = new SignerIdentifierInfo(signer.SignerID.Issuer, new DerInteger(signer.SignerID.SerialNumber));
    _digestAlgorithm = new AlgorithmInfo(signer.DigestAlgorithmID);
    _authenticatedAttributes = signer.SignedAttributes.ToAttributes().GetAttributes()
      .Select(AttributeInfo.GetInstance).ToList();
    _digestEncryptionAlgorithm = new AlgorithmInfo(signer.EncryptionAlgorithmID);
    _encryptedDigest = TextualInfo.GetInstance(signer.ToSignerInfo().EncryptedDigest);
    _unauthenticatedAttributes = signer.UnsignedAttributes?.ToAttributes().GetAttributes()
      .Select(AttributeInfo.GetInstance).ToList();
  }

  public Asn1Encodable ToPrimitive()
  {
    var authenticatedAttributesDerSet = _authenticatedAttributes.ToPrimitiveDerSet();
    var unauthenticatedAttributesDerSet = _unauthenticatedAttributes?.ToPrimitiveDerSet();

    return new List<Asn1Encodable?>
    {
      new DerInteger(_version),
      _sid.ToPrimitive(),
      _digestAlgorithm.ToPrimitive(),
      TaggedObjectInfo.GetTaggedObject(false, 0, authenticatedAttributesDerSet),
      _digestEncryptionAlgorithm.ToPrimitive(),
      _encryptedDigest.ToPrimitive(),
      unauthenticatedAttributesDerSet != null
        ? TaggedObjectInfo.GetTaggedObject(false, 1, unauthenticatedAttributesDerSet)
        : null
    }.ToDerSequence();
  }
}