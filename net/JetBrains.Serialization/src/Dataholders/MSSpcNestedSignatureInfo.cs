using Newtonsoft.Json;
using Org.BouncyCastle.Asn1;
using Attribute = Org.BouncyCastle.Asn1.Cms.Attribute;

namespace JetBrains.Serialization;

[JsonObject(MemberSerialization.OptIn)]
public class MSSpcNestedSignatureInfo : AttributeInfo
{
  [JsonProperty("Identifier")] public override TextualInfo Identifier { get; }
  [JsonProperty("Content")] public List<RSASignedDataInfo> Content { get; }

  [JsonConstructor]
  public MSSpcNestedSignatureInfo(TextualInfo identifier, List<RSASignedDataInfo> content)
  {
    Identifier = identifier;
    Content = content;
  }

  public MSSpcNestedSignatureInfo(Attribute attribute)
    : this(TextualInfo.GetInstance(attribute.AttrType),
      attribute.AttrValues.ToArray().Select(av => RSASignedDataInfo.GetInstance(av as DerSequence)).ToList())
  {
  }

  public override Asn1Encodable GetPrimitiveContent()
    => Content.ToPrimitiveDerSet();
}