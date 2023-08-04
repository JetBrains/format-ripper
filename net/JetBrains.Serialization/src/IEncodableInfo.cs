namespace JetBrains.Serialization;

using Org.BouncyCastle.Asn1;

public interface IEncodableInfo
{
  Asn1Encodable ToPrimitive();
}