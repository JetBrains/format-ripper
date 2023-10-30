using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Math;

namespace JetBrains.Serialization;

public abstract class TextualInfo
{
  private static readonly Dictionary<Type, Func<Asn1Encodable, string>> ToStringMethods
    = new Dictionary<Type, Func<Asn1Encodable, string>>
    {
      { typeof(DerBitString), x => ((DerBitString)x).GetOctets().ToHexString() },
      { typeof(DerEnumerated), x => ((DerEnumerated)x).Value.ToString() },
      { typeof(DerInteger), x => ((DerInteger)x).Value.ToString() },
      { typeof(DerBoolean), x => ((DerBoolean)x).IsTrue.ToString() },
      { typeof(DerObjectIdentifier), x => ((DerObjectIdentifier)x).Id },
      { typeof(DerGeneralString), x => ((DerGeneralString)x).GetString() },
      { typeof(DerNumericString), x => ((DerNumericString)x).GetString() },
      { typeof(DerVisibleString), x => ((DerVisibleString)x).GetString() },
      { typeof(DerBmpString), x => ((DerBmpString)x).GetString() },
      { typeof(DerIA5String), x => ((DerIA5String)x).GetString() },
      { typeof(DerUtf8String), x => ((DerUtf8String)x).GetString() },
      { typeof(DerPrintableString), x => ((DerPrintableString)x).GetString() },
      { typeof(DerOctetString), x => ((DerOctetString)x).GetOctets().ToHexString() },
      { typeof(DerUniversalString), x => ((DerUniversalString)x).GetOctets().ToHexString() },
      { typeof(DerGeneralizedTime), x => ((DerGeneralizedTime)x).ToDateTime().ToString() },
      { typeof(DerUtcTime), x => ((DerUtcTime)x).ToDateTime().ToString() },
      { typeof(DerNull), x => "NULL" }
    };

  private static readonly Dictionary<Type, string> AsnTypeNames
    = new Dictionary<Type, string>
    {
      { typeof(DerBitString), "BitString" },
      { typeof(DerEnumerated), "Enumerated" },
      { typeof(DerInteger), "Integer" },
      { typeof(DerBoolean), "Boolean" },
      { typeof(DerObjectIdentifier), "ObjectIdentifier" },
      { typeof(DerGeneralString), "GeneralString" },
      { typeof(DerNumericString), "NumericString" },
      { typeof(DerVisibleString), "VisibleString" },
      { typeof(DerBmpString), "BmpString" },
      { typeof(DerIA5String), "IA5String" },
      { typeof(DerUtf8String), "Utf8String" },
      { typeof(DerPrintableString), "PrintableString" },
      { typeof(DerOctetString), "OctetString" },
      { typeof(DerUniversalString), "UniversalString" },
      { typeof(DerGeneralizedTime), "GeneralizedTime" },
      { typeof(DerUtcTime), "UtcTime" },
      { typeof(DerNull), "Null" }
    };

  private static readonly Dictionary<string, Func<string, Asn1Encodable>> FromStringMethods
    = new Dictionary<string, Func<string, Asn1Encodable>>
    {
      { "BitString", str => new DerBitString(str.HexToBytes()) },
      { "Enumerated", str => new DerEnumerated(new BigInteger(str)) },
      { "Integer", str => new DerInteger(new BigInteger(str)) },
      { "Boolean", str => DerBoolean.GetInstance(bool.Parse(str)) },
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
      { "GeneralizedTime", str => new DerGeneralizedTime(DateTime.Parse(str)) },
      { "UtcTime", str => new DerUtcTime(DateTime.Parse(str)) },
      { "Null", _ => DerNull.Instance }
    };


  public static String GetType(Asn1Object value)
  {
    if (AsnTypeNames.TryGetValue(value.GetType(), out var typeName))
    {
      return typeName;
    }

    return "unknown";
  }

  public static String GetStringValue(Asn1Object value)
  {
    if (ToStringMethods.TryGetValue(value.GetType(), out var func))
    {
      return func(value);
    }

    return "unknown";
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