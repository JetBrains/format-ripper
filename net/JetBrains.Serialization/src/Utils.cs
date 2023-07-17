using System.Collections.Generic;
using System.Linq;
using System.Text;
using Org.BouncyCastle.Asn1;

namespace JetBrains.Serialization;

public static class AsnExtensions
{
  public static List<Asn1Encodable?> ToPrimitiveList(this List<IEncodableInfo?> source) =>
    source.Select(item => item?.ToPrimitive()).ToList();

  public static DerSequence ToDlSequence(this List<Asn1Encodable?> source)
  {
    Asn1EncodableVector vector = new Asn1EncodableVector();
    vector.Add(source.Where(item => item != null).ToArray());

    return new DerSequence(vector);
  }

  public static DerSet ToDlSet(this List<Asn1Encodable?> source)
  {
    Asn1EncodableVector vector = new Asn1EncodableVector();
    vector.Add(source.Where(item => item != null).ToArray());

    return new DerSet(vector);
  }

  public static string ToHexString(this byte[] bytes)
  {
    var hexChars = "0123456789ABCDEF";
    var result = new StringBuilder(bytes.Length * 2);

    foreach (var b in bytes)
    {
      var value = b & 0xFF;
      result.Append(hexChars[value >> 4]);
      result.Append(hexChars[value & 0x0F]);
    }

    return result.ToString();
  }
}