using Org.BouncyCastle.Asn1;

namespace JetBrains.SignatureVerifier.Crypt
{
    public static class OIDs
    {
        public static readonly DerObjectIdentifier SPC_INDIRECT_DATA = new("1.3.6.1.4.1.311.2.1.4");
        public static readonly DerObjectIdentifier SPC_NESTED_SIGNATURE = new("1.3.6.1.4.1.311.2.4.1");
        public static readonly DerObjectIdentifier SIGNING_TIME = new("1.2.840.113549.1.9.5");
        public static readonly DerObjectIdentifier MS_COUNTER_SIGN = new("1.3.6.1.4.1.311.3.3.1");
        public static readonly DerObjectIdentifier EXTENDED_KEY_USAGE = new("2.5.29.37");
    }
}