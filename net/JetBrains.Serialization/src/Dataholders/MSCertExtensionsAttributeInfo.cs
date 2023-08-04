using Newtonsoft.Json;
using Org.BouncyCastle.Asn1;
using Attribute = Org.BouncyCastle.Asn1.Cms.Attribute;
using JetBrains.Serialization;

[JsonObject(MemberSerialization.Fields)]
public class MSCertExtensionsAttributeInfo : AttributeInfo
{
  public override TextualInfo Identifier { get; }
  public List<List<TextualInfo>> Content { get; }

  public MSCertExtensionsAttributeInfo(Attribute attribute)
  {
    Identifier = TextualInfo.GetInstance(attribute.AttrType);
    Content = attribute.AttrValues.ToArray().OfType<Asn1Sequence>().Select(seq =>
      seq.OfType<Asn1Encodable>().Select(val => TextualInfo.GetInstance(val)).ToList()).ToList();
  }

  public override Asn1Encodable GetPrimitiveContent() =>
    Content.Select(list => list.ToPrimitiveDerSequence()).ToDerSet();
}