using System.Collections;
using System.Text;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Cms;
using Org.BouncyCastle.Asn1.CryptoPro;
using Org.BouncyCastle.Asn1.Nist;
using Org.BouncyCastle.Asn1.Oiw;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.TeleTrust;
using ContentInfo = Org.BouncyCastle.Asn1.Pkcs.ContentInfo;
using SignedData = Org.BouncyCastle.Asn1.Cms.SignedData;

namespace JetBrains.Serialization;

public static class AsnExtensions
{
  public static IList<Asn1Encodable?> ToPrimitiveList(this IEnumerable<IEncodableInfo?> source) =>
    source.Select(item => item?.ToPrimitive()).ToList();

  public static DerSequence ToPrimitiveDerSequence(this IEnumerable<IEncodableInfo?> source) =>
    source.ToPrimitiveList().ToDerSequence();

  public static DerSet ToPrimitiveDerSet(this IEnumerable<IEncodableInfo?> source) =>
    source.ToPrimitiveList().ToDerSet();

  public static DerSequence ToDerSequence(this IEnumerable<Asn1Encodable?> source)
  {
    Asn1EncodableVector vector = new Asn1EncodableVector { source.Where(item => item != null).ToArray() };

    return new DerSequence(vector);
  }

  /*
   * This is a HACK to create DerSet with the exact order of elements, we provide.
   * We need this, because sorting seems to work wrong with BER encoding (mach-O files).
   */
  public static DerSet ToDerSet(this IEnumerable<Asn1Encodable?> source)
  {
    var sequence = source.ToDerSequence();
    var tagged = TaggedObjectInfo.GetTaggedObject(false, 0, sequence);

    return (DerSet)Asn1Set.GetInstance(tagged, false);
  }

  public static ContentInfo ToContentInfo(this SignedData signedData, string encoding = "BER")
  {
    var signedDataBytes = signedData.GetEncoded(encoding);
    using var memoryStream = new MemoryStream(signedDataBytes);
    var asn1Stream = new Asn1InputStream(memoryStream);
    var asn1Object = asn1Stream.ReadObject();

    return new ContentInfo(CmsObjectIdentifiers.SignedData, asn1Object);
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
      digestOidToNames.Add(NistObjectIdentifiers.IdSha512_256, "SHA-512/256");
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