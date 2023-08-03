using Newtonsoft.Json;
using Org.BouncyCastle.Asn1;
using Attribute = Org.BouncyCastle.Asn1.Cms.Attribute;

namespace JetBrains.Serialization;

[JsonObject(MemberSerialization.Fields)]
public class MSSpcNestedSignatureInfo : AttributeInfo
{
  public override TextualInfo Identifier { get; }
  public List<RSASignedDataInfo> Content { get; }

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
    => Content.Select(c => c.ToPrimitive()).ToArray().ToList().ToDerSet();
}