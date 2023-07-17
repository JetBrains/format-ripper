using System.Collections.Generic;
using System.Linq;
using Org.BouncyCastle.Asn1;

namespace JetBrains.SignatureVerifier.Serialization;

public static class AsnExtensions
{
  public static List<Asn1Encodable> ToPrimitiveList(this List<IEncodableInfo> source) =>
    source.Select(item => item.ToPrimitive()).ToList();

  public static DerSequence ToDlSequence(this List<Asn1Encodable> source)
  {
    Asn1EncodableVector vector = new Asn1EncodableVector();
    vector.Add(source.Where(item => item != null).ToArray());

    return new DerSequence(vector);
  }

  public static DerSet ToDlSet(this List<Asn1Encodable> source)
  {
    Asn1EncodableVector vector = new Asn1EncodableVector();
    vector.Add(source.Where(item => item != null).ToArray());

    return new DerSet(vector);
  }
}