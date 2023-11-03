using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Math;

namespace JetBrains.Serialization;

public abstract class TextualInfo
{
  private static readonly Dictionary<Type, KeyValuePair<string, Func<Asn1Encodable, string>>> AsnToString
    = new Dictionary<Type, KeyValuePair<string, Func<Asn1Encodable, string>>>
    {
      {
        typeof(DerBitString),
        new KeyValuePair<string, Func<Asn1Encodable, string>>("BitString",
          x => ((DerBitString)x).GetOctets().ToHexString())
      },
      {
        typeof(DerEnumerated),
        new KeyValuePair<string, Func<Asn1Encodable, string>>("Enumerated", x => ((DerEnumerated)x).Value.ToString())
      },
      {
        typeof(DerInteger),
        new KeyValuePair<string, Func<Asn1Encodable, string>>("Integer", x => ((DerInteger)x).Value.ToString())
      },
      {
        typeof(DerObjectIdentifier),
        new KeyValuePair<string, Func<Asn1Encodable, string>>("ObjectIdentifier", x => ((DerObjectIdentifier)x).Id)
      },
      {
        typeof(DerGeneralString),
        new KeyValuePair<string, Func<Asn1Encodable, string>>("GeneralString", x => ((DerGeneralString)x).GetString())
      },
      {
        typeof(DerNumericString),
        new KeyValuePair<string, Func<Asn1Encodable, string>>("NumericString", x => ((DerNumericString)x).GetString())
      },
      {
        typeof(DerVisibleString),
        new KeyValuePair<string, Func<Asn1Encodable, string>>("VisibleString", x => ((DerVisibleString)x).GetString())
      },
      {
        typeof(DerBmpString),
        new KeyValuePair<string, Func<Asn1Encodable, string>>("BmpString", x => ((DerBmpString)x).GetString())
      },
      {
        typeof(DerIA5String),
        new KeyValuePair<string, Func<Asn1Encodable, string>>("IA5String", x => ((DerIA5String)x).GetString())
      },
      {
        typeof(DerUtf8String),
        new KeyValuePair<string, Func<Asn1Encodable, string>>("Utf8String", x => ((DerUtf8String)x).GetString())
      },
      {
        typeof(DerPrintableString),
        new KeyValuePair<string, Func<Asn1Encodable, string>>("PrintableString",
          x => ((DerPrintableString)x).GetString())
      },
      {
        typeof(DerOctetString),
        new KeyValuePair<string, Func<Asn1Encodable, string>>("OctetString",
          x => ((DerOctetString)x).GetOctets().ToHexString())
      },
      {
        typeof(DerUniversalString),
        new KeyValuePair<string, Func<Asn1Encodable, string>>("UniversalString",
          x => ((DerUniversalString)x).GetOctets().ToHexString())
      },
      {
        typeof(DerGraphicString),
        new KeyValuePair<string, Func<Asn1Encodable, string>>("GraphicString",
          x => ((DerGraphicString)x).GetOctets().ToHexString())
      },
      {
        typeof(DerGeneralizedTime),
        new KeyValuePair<string, Func<Asn1Encodable, string>>("GeneralizedTime",
          x => ((DerGeneralizedTime)x).ToDateTime().ToString())
      },
      {
        typeof(DerUtcTime),
        new KeyValuePair<string, Func<Asn1Encodable, string>>("UtcTime", x => ((DerUtcTime)x).ToDateTime().ToString())
      },
      { typeof(DerNull), new KeyValuePair<string, Func<Asn1Encodable, string>>("Null", x => "NULL") }
    };

  private static readonly Dictionary<string, Func<string, Asn1Encodable>> FromStringMethods
    = new Dictionary<string, Func<string, Asn1Encodable>>
    {
      { "BitString", str => new DerBitString(str.HexToBytes()) },
      { "Enumerated", str => new DerEnumerated(new BigInteger(str)) },
      { "Integer", str => new DerInteger(new BigInteger(str)) },
      { "ObjectIdentifier", str => new DerObjectIdentifier(str) },
      { "GeneralString", str => new DerGeneralString(str) },
      { "NumericString", str => new DerNumericString(str) },
      { "VisibleString", str => new DerVisibleString(str) },
      { "BmpString", str => new DerBmpString(str) },
      { "IA5String", str => new DerIA5String(str) },
      { "Utf8String", str => new DerUtf8String(str) },
      { "PrintableString", str => new DerPrintableString(str) },
      { "OctetString", str => new DerOctetString(str.HexToBytes()) },
      { "UniversalString", str => new DerUniversalString(str.HexToBytes()) },
      { "GraphicString", str => new DerGraphicString(str.HexToBytes()) },
      { "GeneralizedTime", str => new DerGeneralizedTime(DateTime.Parse(str)) },
      { "UtcTime", str => new DerUtcTime(DateTime.Parse(str)) },
      { "Null", _ => DerNull.Instance }
    };


  public static String GetType(Asn1Object value)
  {
    if (AsnToString.TryGetValue(value.GetType(), out var entry))
    {
      return entry.Key;
    }

    throw new Exception();
  }

  public static String GetStringValue(Asn1Object value)
  {
    if (AsnToString.TryGetValue(value.GetType(), out var entry))
    {
      return entry.Value(value);
    }

    throw new Exception();
  }

  public static Asn1Encodable GetEncodable(string type, string value)
  {
    if (FromStringMethods.TryGetValue(type, out var func))
    {
      return func(value);
    }

    return DerNull.Instance;
  }
}