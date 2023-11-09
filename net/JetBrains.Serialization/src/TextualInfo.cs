using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Math;

namespace JetBrains.Serialization;

public abstract class TextualInfo
{
  public static String GetTaggedValue(Asn1Object value)
  {
    switch (value)
    {
      case DerBitString x:
        return $"[BitString] {x.GetOctets().ToHexString()}";
      case DerEnumerated x:
        return $"[Enumerated] {x.Value}";
      case DerInteger x:
        return $"[Integer] {x.Value}";
      case DerObjectIdentifier x:
        return $"[ObjectIdentifier] {x.Id}";
      case DerGeneralString x:
        return $"[GeneralString] {x.GetString()}";
      case DerNumericString x:
        return $"[NumericString] {x.GetString()}";
      case DerVisibleString x:
        return $"[VisibleString] {x.GetString()}";
      case DerT61String x:
        return $"[T61String] {x.GetString()}";
      case DerBmpString x:
        return $"[BmpString] {x.GetString()}";
      case DerIA5String x:
        return $"[IA5String] {x.GetString()}";
      case DerUtf8String x:
        return $"[Utf8String] {x.GetString()}";
      case DerPrintableString x:
        return $"[PrintableString] {x.GetString()}";
      case DerOctetString x:
        return $"[OctetString] {x.GetOctets().ToHexString()}";
      case DerUniversalString x:
        return $"[UniversalString] {x.GetOctets().ToHexString()}";
      case DerGraphicString x:
        return $"[GraphicString] {x.GetOctets().ToHexString()}";
      case DerVideotexString x:
        return $"[VideotexString] {x.GetOctets().ToHexString()}";
      case DerGeneralizedTime x:
        return $"[GeneralizedTime] {x.ToDateTime()}";
      case DerUtcTime x:
        return $"[UtcTime] {x.ToDateTime()}";
      case DerNull:
        return "[Null] NULL";
      default:
        throw new ArgumentException($"Unknown ASN type: {value.GetType()}");
    }
  }

  public static Asn1Encodable GetEncodable(string type, string value)
  {
    switch (type)
    {
      case "BitString":
        return new DerBitString(value.HexToBytes());
      case "Enumerated":
        return new DerEnumerated(new BigInteger(value));
      case "Integer":
        return new DerInteger(new BigInteger(value));
      case "ObjectIdentifier":
        return new DerObjectIdentifier(value);
      case "GeneralString":
        return new DerGeneralString(value);
      case "NumericString":
        return new DerNumericString(value);
      case "VisibleString":
        return new DerVisibleString(value);
      case "T61String":
        return new DerT61String(value);
      case "BmpString":
        return new DerBmpString(value);
      case "IA5String":
        return new DerIA5String(value);
      case "Utf8String":
        return new DerUtf8String(value);
      case "PrintableString":
        return new DerPrintableString(value);
      case "OctetString":
        return new DerOctetString(value.HexToBytes());
      case "VideotexString":
        return new DerVideotexString(value.HexToBytes());
      case "UniversalString":
        return new DerUniversalString(value.HexToBytes());
      case "GraphicString":
        return new DerGraphicString(value.HexToBytes());
      case "GeneralizedTime":
        return new DerGeneralizedTime(DateTime.Parse(value));
      case "UtcTime":
        return new DerUtcTime(DateTime.Parse(value));
      case "Null":
        return DerNull.Instance;
      default:
        throw new ArgumentException($"Unknown object type: {type}");
    }
  }
}