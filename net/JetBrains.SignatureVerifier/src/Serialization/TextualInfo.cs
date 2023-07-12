using System;
using System.Collections.Generic;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Math;

namespace JetBrains.SignatureVerifier.Serialization;

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
      case DerNull _:
        return new Asn1NullInfo("NULL");
      default:
        throw new Exception($"{value.GetType().Name} is not handled in the factory method.");
    }
  }

  protected abstract Asn1Encodable ToEncodable();

  public Asn1Encodable ToPrimitive() => ToEncodable().ToAsn1Object();
}

public abstract class DateTextualInfo : TextualInfo
{
  protected DateTime Content { get; set; }
}

public class Asn1UtcTimeInfo : DateTextualInfo
{
  public Asn1UtcTimeInfo(DateTime content) => this.Content = content;
  protected override Asn1Encodable ToEncodable() => new DerUtcTime(Content);
}

public class Asn1GeneralizedTimeInfo : DateTextualInfo
{
  public Asn1GeneralizedTimeInfo(DateTime content) => this.Content = content;
  protected override Asn1Encodable ToEncodable() => new DerGeneralizedTime(Content);
}

public abstract class HexTextualInfo : TextualInfo
{
  protected byte[] Content { get; set; }
}

public class DerUniversalStringInfo : HexTextualInfo
{
  public DerUniversalStringInfo(byte[] content) => this.Content = content;
  protected override Asn1Encodable ToEncodable() => new DerUniversalString(Content);
}

public class DerOctetStringInfo : HexTextualInfo
{
  public DerOctetStringInfo(byte[] content) => this.Content = content;
  protected override Asn1Encodable ToEncodable() => new DerOctetString(Content);
}

public class DerBitStringInfo : HexTextualInfo
{
  public DerBitStringInfo(byte[] content) => this.Content = content;
  protected override Asn1Encodable ToEncodable() => new DerBitString(Content);
}

public abstract class StringTextualInfo : TextualInfo
{
  protected string Content { get; set; }
}

public class DerPrintableStringInfo : StringTextualInfo
{
  public DerPrintableStringInfo(string content) => this.Content = content;
  protected override Asn1Encodable ToEncodable() => new DerPrintableString(Content);
}

public class DerUTF8StringInfo : StringTextualInfo
{
  public DerUTF8StringInfo(string content) => this.Content = content;
  protected override Asn1Encodable ToEncodable() => new DerUtf8String(Content);
}

public class DerIA5StringInfo : StringTextualInfo
{
  public DerIA5StringInfo(string content) => this.Content = content;
  protected override Asn1Encodable ToEncodable() => new DerIA5String(Content);
}

public class DerBmpStringInfo : StringTextualInfo
{
  public DerBmpStringInfo(string content) => this.Content = content;
  protected override Asn1Encodable ToEncodable() => new DerBmpString(Content);
}

public class DerVisibleStringInfo : StringTextualInfo
{
  public DerVisibleStringInfo(string content) => this.Content = content;
  protected override Asn1Encodable ToEncodable() => new DerVisibleString(Content);
}

public class DerNumericStringInfo : StringTextualInfo
{
  public DerNumericStringInfo(string content) => this.Content = content;
  protected override Asn1Encodable ToEncodable() => new DerNumericString(Content);
}

public class DerGeneralStringInfo : StringTextualInfo
{
  public DerGeneralStringInfo(string content) => this.Content = content;
  protected override Asn1Encodable ToEncodable() => new DerGeneralString(Content);
}

public class Asn1ObjectIdentifierInfo : StringTextualInfo
{
  public Asn1ObjectIdentifierInfo(string content) => this.Content = content;
  protected override Asn1Encodable ToEncodable() => new DerObjectIdentifier(Content);
}

public class BooleanInfo : TextualInfo
{
  private bool Content { get; }
  public BooleanInfo(bool content) => this.Content = content;

  protected override Asn1Encodable ToEncodable() =>
    DerBoolean.GetInstance(Content);
}
public class IntegerInfo : StringTextualInfo
{
  public IntegerInfo(string content) => this.Content = content;
  protected override Asn1Encodable ToEncodable() => new DerInteger(new BigInteger(Content));
}

public class Asn1NullInfo : StringTextualInfo
{
  public Asn1NullInfo(string content) => this.Content = content;
  protected override Asn1Encodable ToEncodable() => DerNull.Instance;
}