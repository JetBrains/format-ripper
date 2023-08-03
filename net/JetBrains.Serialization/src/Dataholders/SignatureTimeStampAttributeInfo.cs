using Newtonsoft.Json;
using Org.BouncyCastle.Asn1;
using Attribute = Org.BouncyCastle.Asn1.Cms.Attribute;

namespace JetBrains.Serialization;

[JsonObject(MemberSerialization.Fields)]
public class SignatureTimeStampAttributeInfo : AttributeInfo
{
  public override TextualInfo Identifier { get; }
  public List<RSASignedDataInfo> Content { get; }

  public SignatureTimeStampAttributeInfo(TextualInfo identifier, List<RSASignedDataInfo> content)
  {
    Identifier = identifier;
    Content = content;
  }

  public SignatureTimeStampAttributeInfo(Attribute attribute)
    : this(TextualInfo.GetInstance(attribute.AttrType),
      attribute.AttrValues.ToArray().Select(av => RSASignedDataInfo.GetInstance(av as DerSequence)).ToList())
  {
  }

  public override Asn1Encodable GetPrimitiveContent() =>
    Content.Cast<IEncodableInfo>().ToList().ToPrimitiveList().ToDerSet();
}