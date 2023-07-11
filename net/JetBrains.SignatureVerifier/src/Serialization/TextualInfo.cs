using System;
using System.Collections.Generic;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Math;

namespace JetBrains.SignatureVerifier.Serialization;

public abstract class ITextualInfo : IEncodableInfo
{
  public static ITextualInfo GetInstance(Asn1Encodable value)
  {
    switch (value)
    {
      case DerUtcTime utcTime:
        return new ASN1UTCTimeInfo(utcTime.ToDateTime());
      case DerGeneralizedTime generalizedTime:
        return new ASN1GeneralizedTimeInfo(generalizedTime.ToDateTime());
      case DerUniversalString universalString:
        return new DERUniversalStringInfo(universalString.GetOctets());
      case DerOctetString octetString:
        return new DEROctetStringInfo(octetString.GetOctets());
      case DerBitString bitString:
        return new DERBitStringInfo(bitString.GetOctets());
      case DerPrintableString printableString:
        return new DERPrintableStringInfo(printableString.GetString());
      case DerUtf8String utf8String:
        return new DERUTF8StringInfo(utf8String.GetString());
      case DerIA5String ia5String:
        return new DERIA5StringInfo(ia5String.GetString());
      case DerBmpString bmpString:
        return new DERBmpStringInfo(bmpString.GetString());
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

  public Asn1Object ToPrimitive() => ToEncodable().ToAsn1Object();
}

public abstract class DateTextualInfo : ITextualInfo
{
  protected DateTime content { get; set; }
}

public class ASN1UTCTimeInfo : DateTextualInfo
{
  public ASN1UTCTimeInfo(DateTime content) => this.content = content;
  protected override Asn1Encodable ToEncodable() => new DerUtcTime(content);
}

public class ASN1GeneralizedTimeInfo : DateTextualInfo
{
  public ASN1GeneralizedTimeInfo(DateTime content) => this.content = content;
  protected override Asn1Encodable ToEncodable() => new DerGeneralizedTime(content);
}

public abstract class HexTextualInfo : ITextualInfo
{
  protected byte[] content { get; set; }
}

public class DERUniversalStringInfo : HexTextualInfo
{
  public DERUniversalStringInfo(byte[] content) => this.content = content;
  protected override Asn1Encodable ToEncodable() => new DerUniversalString(content);
}

public class DEROctetStringInfo : HexTextualInfo
{
  public DEROctetStringInfo(byte[] content) => this.content = content;
  protected override Asn1Encodable ToEncodable() => new DerOctetString(content);
}

public class DERBitStringInfo : HexTextualInfo
{
  public DERBitStringInfo(byte[] content) => this.content = content;
  protected override Asn1Encodable ToEncodable() => new DerBitString(content);
}

public abstract class StringTextualInfo : ITextualInfo
{
  protected string content { get; set; }
}

public class DERPrintableStringInfo : StringTextualInfo
{
  public DERPrintableStringInfo(string content) => this.content = content;
  protected override Asn1Encodable ToEncodable() => new DerPrintableString(content);
}

public class DERUTF8StringInfo : StringTextualInfo
{
  public DERUTF8StringInfo(string content) => this.content = content;
  protected override Asn1Encodable ToEncodable() => new DerUtf8String(content);
}

public class DERIA5StringInfo : StringTextualInfo
{
  public DERIA5StringInfo(string content) => this.content = content;
  protected override Asn1Encodable ToEncodable() => new DerIA5String(content);
}

public class DERBmpStringInfo : StringTextualInfo
{
  public DERBmpStringInfo(string content) => this.content = content;
  protected override Asn1Encodable ToEncodable() => new DerBmpString(content);
}

public class DerVisibleStringInfo : StringTextualInfo
{
  public DerVisibleStringInfo(string content) => this.content = content;
  protected override Asn1Encodable ToEncodable() => new DerVisibleString(content);
}

public class DerNumericStringInfo : StringTextualInfo
{
  public DerNumericStringInfo(string content) => this.content = content;
  protected override Asn1Encodable ToEncodable() => new DerNumericString(content);
}

public class DerGeneralStringInfo : StringTextualInfo
{
  public DerGeneralStringInfo(string content) => this.content = content;
  protected override Asn1Encodable ToEncodable() => new DerGeneralString(content);
}

public class Asn1ObjectIdentifierInfo : StringTextualInfo
{
  public Asn1ObjectIdentifierInfo(string content) => this.content = content;
  protected override Asn1Encodable ToEncodable() => new DerObjectIdentifier(content);
}

public class BooleanInfo : ITextualInfo
{
  private bool content { get; }
  public BooleanInfo(bool content) => this.content = content;

  protected override Asn1Encodable ToEncodable() =>
    DerBoolean.GetInstance(content);
}
public class IntegerInfo : StringTextualInfo
{
  public IntegerInfo(string content) => this.content = content;
  protected override Asn1Encodable ToEncodable() => new DerInteger(new BigInteger(content));
}

public class Asn1NullInfo : StringTextualInfo
{
  public Asn1NullInfo(string content) => this.content = content;
  protected override Asn1Encodable ToEncodable() => DerNull.Instance;
}