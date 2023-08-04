using System;
using System.Collections.Generic;
using Newtonsoft.Json;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Math;

namespace JetBrains.Serialization;

[JsonObject(MemberSerialization.OptIn)]
public abstract class TextualInfo : IEncodableInfo
{
  public static TextualInfo GetInstance(Asn1Encodable value)
  {
    switch (value)
    {
      case DerUtcTime utcTime:
        return new Asn1UtcTimeInfo(utcTime.ToDateTime());
      case DerGeneralizedTime generalizedTime:
        return new Asn1GeneralizedTimeInfo(generalizedTime.ToDateTime());
      case DerUniversalString universalString:
        return new DerUniversalStringInfo(universalString.GetOctets());
      case DerOctetString octetString:
        return new DerOctetStringInfo(octetString.GetOctets());
      case DerBitString bitString:
        return new DerBitStringInfo(bitString.GetOctets());
      case DerPrintableString printableString:
        return new DerPrintableStringInfo(printableString.GetString());
      case DerUtf8String utf8String:
        return new DerUTF8StringInfo(utf8String.GetString());
      case DerIA5String ia5String:
        return new DerIA5StringInfo(ia5String.GetString());
      case DerBmpString bmpString:
        return new DerBmpStringInfo(bmpString.GetString());
      case DerVisibleString visibleString:
        return new DerVisibleStringInfo(visibleString.GetString());
      case DerNumericString numericString:
        return new DerNumericStringInfo(numericString.ToString());
      case DerGeneralString generalString:
        return new DerGeneralStringInfo(generalString.ToString());
      case DerObjectIdentifier objectId:
        return new Asn1ObjectIdentifierInfo(objectId.ToString());
      case DerBoolean boolean:
        return new BooleanInfo(boolean.IsTrue);
      case DerInteger integer:
        return new IntegerInfo(integer.ToString());
      case DerEnumerated enumerated:
        return new EnumeratedInfo(enumerated.Value);
      case DerNull _:
        return new Asn1NullInfo("NULL");
      default:
        throw new Exception($"{value.GetType().Name} is not handled in the factory method.");
    }
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