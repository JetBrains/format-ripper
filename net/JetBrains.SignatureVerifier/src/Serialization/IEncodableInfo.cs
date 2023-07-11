namespace JetBrains.SignatureVerifier.Serialization;
using Org.BouncyCastle.Asn1;

public interface IEncodableInfo
{
  Asn1Object ToPrimitive();
}