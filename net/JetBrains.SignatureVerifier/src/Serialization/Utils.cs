using System.Collections.Generic;
using System.Linq;
using JetBrains.SignatureVerifier.Serialization;
using Org.BouncyCastle.Asn1;

namespace ExtensionMethods
{
  public static class AsnExtensions
  {
    public static List<Asn1Object> ToPrimitiveList(this List<IEncodableInfo> source) =>
      source.Select(item => item.ToPrimitive()).ToList();

    public static DerSequence ToDLSequence(this List<Asn1Encodable> source)
    {
      Asn1EncodableVector vector = new Asn1EncodableVector();
      vector.Add(source.Where(item => item != null).ToArray());

      return new DerSequence(vector);
    }

    public static DerSet ToDLSet(this List<Asn1Encodable> source)
    {
      Asn1EncodableVector vector = new Asn1EncodableVector();
      vector.Add(source.Where(item => item != null).ToArray());

      return new DerSet(vector);
    }
  }
}