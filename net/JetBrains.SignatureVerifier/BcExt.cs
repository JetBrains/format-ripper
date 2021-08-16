using System;
using Org.BouncyCastle.Asn1;

namespace JetBrains.SignatureVerifier.Ext
{
    public static class BcExt
    {
        public static string Dump(this Asn1Encodable asn1) => Org.BouncyCastle.Asn1.Utilities.Asn1Dump.DumpAsString(asn1);
        public static void DumpToConsole(this Asn1Encodable asn1) => Console.WriteLine(Dump(asn1));
    }
}