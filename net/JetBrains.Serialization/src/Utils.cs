using System.Collections;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.CryptoPro;
using Org.BouncyCastle.Asn1.Nist;
using Org.BouncyCastle.Asn1.Oiw;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.TeleTrust;

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

public static class SerializationUtils
{
  private static IDictionary digestOidToNames = new Hashtable();

  public static String AlgorithmNameFromId(DerObjectIdentifier identifier)
  {
    if (digestOidToNames.Count == 0)
    {
      digestOidToNames.Add(OiwObjectIdentifiers.IdSha1, "SHA-1");
      digestOidToNames.Add(NistObjectIdentifiers.IdSha224, "SHA-224");
      digestOidToNames.Add(NistObjectIdentifiers.IdSha256, "SHA-256");
      digestOidToNames.Add(NistObjectIdentifiers.IdSha384, "SHA-384");
      digestOidToNames.Add(NistObjectIdentifiers.IdSha512, "SHA-512");
      digestOidToNames.Add(NistObjectIdentifiers.IdSha512_224, "SHA-512/224");
      digestOidToNames.Add(NistObjectIdentifiers.IdSha512_224, "SHA-512(224)");
      digestOidToNames.Add(NistObjectIdentifiers.IdSha512_256, "SHA-512/256");
      digestOidToNames.Add(NistObjectIdentifiers.IdSha512_256, "SHA-512(256)");
      digestOidToNames.Add(OiwObjectIdentifiers.IdSha1, "SHA1");
      digestOidToNames.Add(NistObjectIdentifiers.IdSha224, "SHA224");
      digestOidToNames.Add(NistObjectIdentifiers.IdSha256, "SHA256");
      digestOidToNames.Add(NistObjectIdentifiers.IdSha384, "SHA384");
      digestOidToNames.Add(NistObjectIdentifiers.IdSha512, "SHA512");
      digestOidToNames.Add(NistObjectIdentifiers.IdSha512_224, "SHA512/224");
      digestOidToNames.Add(NistObjectIdentifiers.IdSha512_224, "SHA512(224)");
      digestOidToNames.Add(NistObjectIdentifiers.IdSha512_256, "SHA512/256");
      digestOidToNames.Add(NistObjectIdentifiers.IdSha512_256, "SHA512(256)");
      digestOidToNames.Add(NistObjectIdentifiers.IdSha3_224, "SHA3-224");
      digestOidToNames.Add(NistObjectIdentifiers.IdSha3_256, "SHA3-256");
      digestOidToNames.Add(NistObjectIdentifiers.IdSha3_384, "SHA3-384");
      digestOidToNames.Add(NistObjectIdentifiers.IdSha3_512, "SHA3-512");
      digestOidToNames.Add(NistObjectIdentifiers.IdShake128, "SHAKE-128");
      digestOidToNames.Add(NistObjectIdentifiers.IdShake256, "SHAKE-256");
      digestOidToNames.Add(CryptoProObjectIdentifiers.GostR3411, "GOST3411");
      digestOidToNames.Add(PkcsObjectIdentifiers.MD2, "MD2");
      digestOidToNames.Add(PkcsObjectIdentifiers.MD4, "MD4");
      digestOidToNames.Add(PkcsObjectIdentifiers.MD5, "MD5");
      digestOidToNames.Add(TeleTrusTObjectIdentifiers.RipeMD128, "RIPEMD128");
      digestOidToNames.Add(TeleTrusTObjectIdentifiers.RipeMD160, "RIPEMD160");
      digestOidToNames.Add(TeleTrusTObjectIdentifiers.RipeMD256, "RIPEMD256");
    }

    if (digestOidToNames.Contains(identifier))
    {
      return digestOidToNames[identifier].ToString();
    }

    return identifier.ToString();
  }
}