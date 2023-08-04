using Newtonsoft.Json;
using Org.BouncyCastle.Asn1;
using Attribute = Org.BouncyCastle.Asn1.Cms.Attribute;
using JetBrains.Serialization;
using System.Collections.Generic;
using System.Linq;
using SignerInformation = JetBrains.SignatureVerifier.Crypt.BC.SignerInformation;

[JsonObject(MemberSerialization.OptIn)]
public class SignerInfo : IEncodableInfo
{
  [JsonProperty("Version")] public int Version { get; }
  [JsonProperty("Sid")] public SignerIdentifierInfo Sid { get; }
  [JsonProperty("DigestAlgorithm")] public AlgorithmInfo DigestAlgorithm { get; }

  [JsonProperty("AuthenticatedAttributes")]
  public List<AttributeInfo> AuthenticatedAttributes { get; }

  [JsonProperty("DigestEncryptionAlgorithm")]
  public AlgorithmInfo DigestEncryptionAlgorithm { get; }

  [JsonProperty("EncryptedDigest")] public TextualInfo EncryptedDigest { get; }

  [JsonProperty("UnauthenticatedAttributes")]
  public List<AttributeInfo>? UnauthenticatedAttributes { get; }

  [JsonConstructor]
  public SignerInfo(int version, SignerIdentifierInfo sid, AlgorithmInfo digestAlgorithm,
    List<AttributeInfo> authenticatedAttributes, AlgorithmInfo digestEncryptionAlgorithm, TextualInfo encryptedDigest,
    List<AttributeInfo>? unauthenticatedAttributes)
  {
    Version = version;
    Sid = sid;
    DigestAlgorithm = digestAlgorithm;
    AuthenticatedAttributes = authenticatedAttributes;
    DigestEncryptionAlgorithm = digestEncryptionAlgorithm;
    EncryptedDigest = encryptedDigest;
    UnauthenticatedAttributes = unauthenticatedAttributes;
  }


  public SignerInfo(SignerInformation signer)
  {
    Version = signer.Version;
    Sid = new SignerIdentifierInfo(signer.SignerID.Issuer, new DerInteger(signer.SignerID.SerialNumber));
    DigestAlgorithm = new AlgorithmInfo(signer.DigestAlgorithmID);
    AuthenticatedAttributes = signer.SignedAttributes.ToAttributes().GetAttributes()
      .Select(attr => AttributeInfo.GetInstance(attr)).ToList();
    DigestEncryptionAlgorithm = new AlgorithmInfo(signer.EncryptionAlgorithmID);
    EncryptedDigest = TextualInfo.GetInstance(signer.ToSignerInfo().EncryptedDigest);
    UnauthenticatedAttributes = signer.UnsignedAttributes?.ToAttributes().GetAttributes()
      .Select(attr => AttributeInfo.GetInstance(attr)).ToList();
  }

  public Asn1Encodable ToPrimitive()
  {
    var authenticatedAttributesDerSet = AuthenticatedAttributes.ToPrimitiveDerSet();
    var unauthenticatedAttributesDerSet = UnauthenticatedAttributes != null
      ? UnauthenticatedAttributes.ToPrimitiveDerSet()
      : null;

    return new List<Asn1Encodable?>
    {
      new DerInteger(Version),
      Sid.ToPrimitive(),
      DigestAlgorithm.ToPrimitive(),
      TaggedObjectInfo.GetTaggedObject(false, 0, authenticatedAttributesDerSet),
      DigestEncryptionAlgorithm.ToPrimitive(),
      EncryptedDigest.ToPrimitive(),
      unauthenticatedAttributesDerSet != null
        ? TaggedObjectInfo.GetTaggedObject(false, 1, unauthenticatedAttributesDerSet)
        : null
    }.ToDerSequence();
  }
}