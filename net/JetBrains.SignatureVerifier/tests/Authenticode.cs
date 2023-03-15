using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;

namespace JetBrains.SignatureVerifier.Tests
{
  public class SpcIndirectDataContent : Asn1Encodable
  {
    private readonly SpcAttributeOptional myData;
    private readonly DigestInfo myMessageDigest;

    public SpcIndirectDataContent(SpcAttributeOptional data, DigestInfo messageDigest)
    {
      myData = data;
      myMessageDigest = messageDigest;
    }

    public override Asn1Object ToAsn1Object()
    {
      return new BerSequence(new Asn1EncodableVector(myData, myMessageDigest));
    }
  }

  public class SpcAttributeOptional : Asn1Encodable
  {
    private readonly DerObjectIdentifier type;
    private readonly Asn1Encodable value;

    public SpcAttributeOptional(DerObjectIdentifier type, Asn1Encodable value)
    {
      this.type = type;
      this.value = value;
    }

    public override Asn1Object ToAsn1Object()
    {
      var v = new Asn1EncodableVector(type);
      if (value != null) v.Add(value);
      return new BerSequence(v);
    }
  }

  public class SpcPeImageData : Asn1Encodable
  {
    private DerBitString flags = new(new byte[0]);
    private SpcLink file = new();

    public override Asn1Object ToAsn1Object()
    {
      return new BerSequence(new Asn1EncodableVector(flags, new DerTaggedObject(0, file)));
    }
  }

  public class SpcLink : Asn1Encodable, IAsn1Choice
  {
    private SpcString file = new("");

    public override Asn1Object ToAsn1Object()
    {
      return new DerTaggedObject(false, 2, file);
    }
  }

  public class SpcString : Asn1Encodable, IAsn1Choice
  {
    private DerBmpString unicode;

    public SpcString(string str)
    {
      unicode = new DerBmpString(str);
    }

    public override Asn1Object ToAsn1Object()
    {
      return new DerTaggedObject(false, 0, unicode);
    }
  }
}