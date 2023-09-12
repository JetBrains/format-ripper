using Newtonsoft.Json;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Math;

namespace JetBrains.Serialization;

[JsonObject(MemberSerialization.OptIn)]
public abstract class TextualInfo : IEncodableInfo
{
  private static readonly Dictionary<Type, Func<Asn1Encodable, TextualInfo>> FactoryMethods
    = new Dictionary<Type, Func<Asn1Encodable, TextualInfo>>
    {
      { typeof(DerBitString), x => new DerBitStringInfo(((DerBitString)x).GetOctets()) },
      { typeof(DerEnumerated), x => new EnumeratedInfo(((DerEnumerated)x).Value) },
      { typeof(DerInteger), x => new IntegerInfo(((DerInteger)x).ToString()) },
      { typeof(DerBoolean), x => new BooleanInfo(((DerBoolean)x).IsTrue) },
      { typeof(DerObjectIdentifier), x => new Asn1ObjectIdentifierInfo(((DerObjectIdentifier)x).Id) },
      { typeof(DerGeneralString), x => new DerGeneralStringInfo(((DerGeneralString)x).GetString()) },
      { typeof(DerNumericString), x => new DerNumericStringInfo(((DerNumericString)x).ToString()) },
      { typeof(DerVisibleString), x => new DerVisibleStringInfo(((DerVisibleString)x).GetString()) },
      { typeof(DerBmpString), x => new DerBmpStringInfo(((DerBmpString)x).GetString()) },
      { typeof(DerIA5String), x => new DerIA5StringInfo(((DerIA5String)x).GetString()) },
      { typeof(DerUtf8String), x => new DerUTF8StringInfo(((DerUtf8String)x).GetString()) },
      { typeof(DerPrintableString), x => new DerPrintableStringInfo(((DerPrintableString)x).GetString()) },
      { typeof(DerOctetString), x => new DerOctetStringInfo(((DerOctetString)x).GetOctets()) },
      { typeof(DerUniversalString), x => new DerUniversalStringInfo(((DerUniversalString)x).GetOctets()) },
      { typeof(DerGeneralizedTime), x => new Asn1GeneralizedTimeInfo(((DerGeneralizedTime)x).ToDateTime()) },
      { typeof(DerUtcTime), x => new Asn1UtcTimeInfo(((DerUtcTime)x).ToDateTime()) },
      { typeof(DerNull), _ => new Asn1NullInfo("NULL") }
    };

  public static TextualInfo GetInstance(Asn1Encodable value)
  {
    if (FactoryMethods.TryGetValue(value.GetType(), out var factoryMethod))
    {
      return factoryMethod(value);
    }

    throw new Exception($"{value.GetType().Name} is not handled in the factory method.");
  }

  protected abstract Asn1Encodable ToEncodable();

  public Asn1Encodable ToPrimitive() => ToEncodable().ToAsn1Object();
}

[JsonObject(MemberSerialization.OptIn)]
public abstract class DateTextualInfo : TextualInfo
{
  [JsonProperty("Content")] protected DateTime Content;
}

[JsonObject(MemberSerialization.OptIn)]
public class Asn1UtcTimeInfo : DateTextualInfo
{
  [JsonConstructor]
  public Asn1UtcTimeInfo(DateTime content) => this.Content = content;

  protected override Asn1Encodable ToEncodable() => new DerUtcTime(Content);
}

[JsonObject(MemberSerialization.OptIn)]
public class Asn1GeneralizedTimeInfo : DateTextualInfo
{
  [JsonConstructor]
  public Asn1GeneralizedTimeInfo(DateTime content) => this.Content = content;

  protected override Asn1Encodable ToEncodable() => new DerGeneralizedTime(Content);
}

[JsonObject(MemberSerialization.OptIn)]
public abstract class HexTextualInfo : TextualInfo
{
  [JsonProperty("Content")] protected byte[] Content;
}

[JsonObject(MemberSerialization.OptIn)]
public class DerUniversalStringInfo : HexTextualInfo
{
  [JsonConstructor]
  public DerUniversalStringInfo(byte[] content) => this.Content = content;

  protected override Asn1Encodable ToEncodable() => new DerUniversalString(Content);
}

[JsonObject(MemberSerialization.OptIn)]
public class DerOctetStringInfo : HexTextualInfo
{
  [JsonConstructor]
  public DerOctetStringInfo(byte[] content) => this.Content = content;

  protected override Asn1Encodable ToEncodable() => new DerOctetString(Content);
}

[JsonObject(MemberSerialization.OptIn)]
public class DerBitStringInfo : HexTextualInfo
{
  [JsonConstructor]
  public DerBitStringInfo(byte[] content) => this.Content = content;

  protected override Asn1Encodable ToEncodable() => new DerBitString(Content);
}

[JsonObject(MemberSerialization.OptIn)]
public abstract class StringTextualInfo : TextualInfo
{
  [JsonProperty("Content")] protected string Content;
}

[JsonObject(MemberSerialization.OptIn)]
public class DerPrintableStringInfo : StringTextualInfo
{
  [JsonConstructor]
  public DerPrintableStringInfo(string content) => this.Content = content;

  protected override Asn1Encodable ToEncodable() => new DerPrintableString(Content);
}

[JsonObject(MemberSerialization.OptIn)]
public class DerUTF8StringInfo : StringTextualInfo
{
  [JsonConstructor]
  public DerUTF8StringInfo(string content) => this.Content = content;

  protected override Asn1Encodable ToEncodable() => new DerUtf8String(Content);
}

[JsonObject(MemberSerialization.OptIn)]
public class DerIA5StringInfo : StringTextualInfo
{
  [JsonConstructor]
  public DerIA5StringInfo(string content) => this.Content = content;

  protected override Asn1Encodable ToEncodable() => new DerIA5String(Content);
}

[JsonObject(MemberSerialization.OptIn)]
public class DerBmpStringInfo : StringTextualInfo
{
  [JsonConstructor]
  public DerBmpStringInfo(string content) => this.Content = content;

  protected override Asn1Encodable ToEncodable() => new DerBmpString(Content);
}

[JsonObject(MemberSerialization.OptIn)]
public class DerVisibleStringInfo : StringTextualInfo
{
  [JsonConstructor]
  public DerVisibleStringInfo(string content) => this.Content = content;

  protected override Asn1Encodable ToEncodable() => new DerVisibleString(Content);
}

[JsonObject(MemberSerialization.OptIn)]
public class DerNumericStringInfo : StringTextualInfo
{
  [JsonConstructor]
  public DerNumericStringInfo(string content) => this.Content = content;

  protected override Asn1Encodable ToEncodable() => new DerNumericString(Content);
}

[JsonObject(MemberSerialization.OptIn)]
public class DerGeneralStringInfo : StringTextualInfo
{
  [JsonConstructor]
  public DerGeneralStringInfo(string content) => this.Content = content;

  protected override Asn1Encodable ToEncodable() => new DerGeneralString(Content);
}

[JsonObject(MemberSerialization.OptIn)]
public class Asn1ObjectIdentifierInfo : StringTextualInfo
{
  [JsonConstructor]
  public Asn1ObjectIdentifierInfo(string content) => this.Content = content;

  protected override Asn1Encodable ToEncodable() => new DerObjectIdentifier(Content);
}

[JsonObject(MemberSerialization.OptIn)]
public class BooleanInfo : TextualInfo
{
  [JsonProperty("Content")] private bool _content;

  [JsonConstructor]
  public BooleanInfo(bool content) => this._content = content;

  protected override Asn1Encodable ToEncodable() =>
    DerBoolean.GetInstance(_content);
}

[JsonObject(MemberSerialization.OptIn)]
public class IntegerInfo : StringTextualInfo
{
  [JsonConstructor]
  public IntegerInfo(string content) => this.Content = content;

  protected override Asn1Encodable ToEncodable() => new DerInteger(new BigInteger(Content));
}

[JsonObject(MemberSerialization.OptIn)]
public class EnumeratedInfo : TextualInfo
{
  [JsonProperty("Content")] protected string Content;

  [JsonConstructor]
  public EnumeratedInfo(string content) => this.Content = content;

  public EnumeratedInfo(BigInteger content) => this.Content = content.ToString();
  protected override Asn1Encodable ToEncodable() => new DerEnumerated(new BigInteger(Content));
}

[JsonObject(MemberSerialization.OptIn)]
public class Asn1NullInfo : StringTextualInfo
{
  [JsonConstructor]
  public Asn1NullInfo(string content) => this.Content = content;

  protected override Asn1Encodable ToEncodable() => DerNull.Instance;
}