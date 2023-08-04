using Newtonsoft.Json;
using Org.BouncyCastle.Asn1;
using Attribute = Org.BouncyCastle.Asn1.Cms.Attribute;
using JetBrains.Serialization;

[JsonObject(MemberSerialization.Fields)]
public class CounterSignatureAttributeInfo : AttributeInfo
{
  public override TextualInfo Identifier { get; }
  public List<CounterSignatureInfo> Content { get; }

  public CounterSignatureAttributeInfo(Attribute attribute)
  {
    Identifier = TextualInfo.GetInstance(attribute.AttrType);
    Content = attribute.AttrValues.ToArray().Select(item => CounterSignatureInfo.GetInstance(item as DerSequence))
      .ToList();
  }

  public override Asn1Encodable GetPrimitiveContent() => Content.ToPrimitiveDerSet();
}