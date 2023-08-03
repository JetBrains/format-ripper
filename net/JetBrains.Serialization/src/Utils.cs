using System.Text;
using Org.BouncyCastle.Asn1;

namespace JetBrains.Serialization;

public static class AsnExtensions
{
  public static List<Asn1Encodable?> ToPrimitiveList(this List<IEncodableInfo?> source) =>
    source.Select(item => item?.ToPrimitive()).ToList();

  public static DerSequence ToDerSequence(this List<Asn1Encodable?> source)
  {
    Asn1EncodableVector vector = new Asn1EncodableVector();
    vector.Add(source.Where(item => item != null).ToArray());

    return new DerSequence(vector);
  }

  /*
   * This is a HACK to create DerSet with the exact order of elements, we provide.
   * We need this, because sorting seems to work wrong with BER encoding (mach-O files).
   */
  public static DerSet ToDerSet(this List<Asn1Encodable?> source)
  {
    var sequence = source.ToDerSequence();
    var tagged = new DerTaggedObject(false , 0, sequence);

    return (DerSet) Asn1Set.GetInstance(tagged, false);
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